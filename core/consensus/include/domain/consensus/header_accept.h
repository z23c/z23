/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * domain/consensus/header_accept.h — pure block-header acceptance
 * structural checks.
 *
 * These checks mirror the PURE branches of the legacy
 * core/modules/validation/check_block::check_block_header_impl() and
 * core/modules/validation/check_block::contextual_check_block_header() — the
 * branches that depend only on the header bytes themselves plus a few
 * caller-supplied scalars (height, prev_MTP, expected difficulty
 * target, expected equihash solution size, "now" upper bound). They do
 * NOT consult any block_index map, system clock, RNG, or I/O.
 *
 * The state-bearing checks left behind in the lib wrapper (and NOT
 * replicated here) are:
 *   - PoW / Equihash signature verification     — needs crypto_registry
 *   - Walking pprev to compute median-time-past — needs block_index
 *   - GetNextWorkRequired (averaging window)    — walks pprev
 *   - Checkpoint lookup                         — already in domain
 *   - GetAdjustedTime()                         — reads system clock
 *
 * Reject reasons emitted by these functions are byte-identical to the
 * P2P-visible strings legacy callers produce ("version-too-low",
 * "bad-version", "time-too-new", "time-too-old",
 * "bad-equihash-solution-size", "bad-diffbits"). They MUST NOT change.
 *
 * Purity contract:
 *   - No clock, no RNG, no I/O, no global state read or write.
 *   - No allocation (all checks operate on inputs in place).
 *   - Same inputs → same outputs, every call.
 *
 * Layering: domain/consensus/ may #include from util/, core/,
 * consensus/, primitives/. This module deliberately stays clear of
 * chain/chainparams.h (the equihash (N,K) lookup) — the caller
 * computes the expected solution size and passes it in.
 */

#ifndef ZCL_DOMAIN_CONSENSUS_HEADER_ACCEPT_H
#define ZCL_DOMAIN_CONSENSUS_HEADER_ACCEPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util/result.h"

struct block_header;

/* Maximum length in bytes (including NUL) of the consensus
 * reject_reason token written back to the caller. Matches
 * `MAX_REJECT_REASON` in consensus/validation.h. Keeping a local
 * constant here avoids dragging that header into the domain include
 * graph for what is otherwise a pure size constant. */
#define DOMAIN_HEADER_ACCEPT_REASON_MAX 256

/* Check that the header's nVersion is at least `min_version`.
 * Mirrors the FIRST gate of legacy check_block_header_impl():
 *   REJECT_IF(header->nVersion < MIN_BLOCK_VERSION,
 *             state, 100, "version-too-low");
 *
 * Outputs:
 *   out_reject_reason — optional. On rejection: "version-too-low".
 *   out_dos — optional. Always 100 on rejection.
 *
 * Pure: no I/O, no global state, no clock, no allocation.
 */
struct zcl_result domain_consensus_check_header_version_too_low(
        const struct block_header *header,
        int32_t min_version,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos);

/* Check that the header's nVersion is not below the minimum
 * "obsolete" line (legacy code uses nVersion >= 4). Mirrors the LAST
 * gate of legacy contextual_check_block_header():
 *   REJECT_OBSOLETE_IF(header->nVersion < 4, state, "bad-version");
 *
 * Note: legacy emits this via REJECT_OBSOLETE_IF with no DoS score
 * (corruption=false, REJECT_OBSOLETE code) — we expose `out_dos = 0`.
 *
 * Outputs:
 *   out_reject_reason — optional. On rejection: "bad-version".
 *   out_dos — optional. Always 0 on rejection.
 *
 * Pure: no I/O, no global state, no clock, no allocation.
 */
struct zcl_result domain_consensus_check_header_version_obsolete(
        const struct block_header *header,
        int32_t obsolete_below,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos);

/* Check that the header's nTime is not in the future beyond
 * `now_upper_bound` (which the caller computes as
 * GetAdjustedTime() + drift, where drift is e.g. 2h). Mirrors the
 * tail gate of legacy check_block_header_impl():
 *   REJECT_INVALID_IF(block_header_get_time(header) >
 *                     GetAdjustedTime() + 2 * 60 * 60,
 *                     state, "time-too-new");
 *
 * Note: legacy emits this via REJECT_INVALID_IF — no DoS, no
 * corruption flag (peer isn't necessarily misbehaving).
 *
 * Outputs:
 *   out_reject_reason — optional. On rejection: "time-too-new".
 *   out_dos — optional. Always 0 on rejection.
 *
 * Pure: no I/O, no global state, no clock, no allocation.
 */
struct zcl_result domain_consensus_check_header_timestamp_too_new(
        const struct block_header *header,
        int64_t now_upper_bound,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos);

/* Check that the header's nTime is strictly greater than `prev_mtp`
 * (the median time of the previous 11 blocks, computed by the caller
 * by walking pprev). Mirrors the MTP gate of legacy
 * contextual_check_block_header():
 *   REJECT_INVALID_IF(
 *       block_header_get_time(header) <=
 *           block_index_get_median_time_past(pindex_prev),
 *       state, "time-too-old");
 *
 * Outputs:
 *   out_reject_reason — optional. On rejection: "time-too-old".
 *   out_dos — optional. Always 0 on rejection.
 *
 * Pure: no I/O, no global state, no clock, no allocation.
 */
struct zcl_result domain_consensus_check_header_timestamp_too_old(
        const struct block_header *header,
        int64_t prev_mtp,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos);

/* Check that the header's nSolutionSize matches the expected size for
 * the height's (N,K) Equihash parameters. The caller passes the
 * expected size (computed from chain_params_equihash_n/k(params,
 * nHeight) via the formula 1<<K * (N/(K+1) + 1) / 8) so this module
 * stays clear of chain/chainparams.h.
 *
 * Mirrors the equihash-size gate of legacy
 * contextual_check_block_header():
 *   if (sol_size > 0) {
 *       size_t expected = ((size_t)1 << eh_k) *
 *                         (eh_n / (eh_k + 1) + 1) / 8;
 *       REJECT_IF(sol_size != expected,
 *                 state, 100, "bad-equihash-solution-size");
 *   }
 *
 * The legacy code only rejects when sol_size > 0; a zero-size header
 * (fast-sync placeholder) silently passes. We replicate that contract
 * — passing sol_size == 0 in the header field skips the check.
 *
 * Outputs:
 *   out_reject_reason — optional. On rejection:
 *     "bad-equihash-solution-size".
 *   out_dos — optional. Always 100 on rejection.
 *
 * Pure: no I/O, no global state, no clock, no allocation.
 */
struct zcl_result domain_consensus_check_header_equihash_solution_size(
        const struct block_header *header,
        size_t expected_solution_size,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos);

/* Check that the header's nBits matches the externally-computed
 * difficulty target. The caller passes `expected_bits` (computed via
 * GetNextWorkRequired which walks the averaging window — explicitly
 * NOT pure, so it stays in the lib wrapper).
 *
 * Mirrors the difficulty gate of legacy
 * contextual_check_block_header():
 *   unsigned int expected_bits = GetNextWorkRequired(...);
 *   if (header->nBits != expected_bits) {
 *       REJECT_IF(true, state, 100, "bad-diffbits");
 *   }
 *
 * Outputs:
 *   out_reject_reason — optional. On rejection: "bad-diffbits".
 *   out_dos — optional. Always 100 on rejection.
 *
 * Pure: no I/O, no global state, no clock, no allocation.
 */
struct zcl_result domain_consensus_check_header_bits_match(
        const struct block_header *header,
        uint32_t expected_bits,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos);

/* Error codes used by domain/consensus/header_accept.{c,h}. Stable
 * across builds; new codes are appended. Returned via zcl_result.code.
 *
 * The numeric range 1301-1399 is reserved for this module so that
 * different domain modules cannot collide on a code value. */
enum domain_consensus_header_accept_err {
    DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_NULL_ARG              = 1301,
    DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_VERSION_TOO_LOW       = 1302,
    DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_BAD_VERSION           = 1303,
    DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_TIME_TOO_NEW          = 1304,
    DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_TIME_TOO_OLD          = 1305,
    DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_BAD_EQUIHASH_SOL_SIZE = 1306,
    DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_BAD_DIFFBITS          = 1307,
};

#endif /* ZCL_DOMAIN_CONSENSUS_HEADER_ACCEPT_H */
