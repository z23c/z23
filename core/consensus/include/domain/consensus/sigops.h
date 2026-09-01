/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * domain/consensus/sigops.h — pure signature-operation counting.
 *
 * Sigop counting is a static walk over transaction scripts. It is a pure
 * function of (transaction, flags) for the legacy count, and a pure
 * function of (transaction, resolved prevouts, flags) for the P2SH count.
 * The P2SH counter never touches a `coins_view_cache`; the caller is
 * responsible for resolving each input's prevout up front. This split is
 * what keeps the domain hexagonally clean — IO/state lives in the
 * core/modules/validation thin wrapper.
 *
 * No clock, no RNG, no I/O, no state reads. Replays from inputs alone.
 *
 * Layering: domain/consensus/ may #include from util/, core/, chain/,
 * consensus/, crypto/, sapling/, script/, primitives/. The fact these
 * functions depend only on primitives/transaction.h and script/script.h
 * is what makes them eligible to live here.
 *
 * Background: zclassicd src/main.cpp::GetLegacySigOpCount and
 * GetP2SHSigOpCount are the historic source-of-truth. The total of the
 * two is what the MAX_BLOCK_SIGOPS consensus limit is checked against.
 */

#ifndef ZCL_DOMAIN_CONSENSUS_SIGOPS_H
#define ZCL_DOMAIN_CONSENSUS_SIGOPS_H

#include <stddef.h>
#include <stdint.h>

#include "util/result.h"

struct transaction;
struct tx_out;

/* Count "legacy" sigops in a transaction — the sum, over every input
 * scriptSig and every output scriptPubKey, of script_get_sig_op_count
 * (which walks the bytecode and counts OP_CHECKSIG / OP_CHECKMULTISIG
 * occurrences, accurate=false). Pure: no side effects.
 *
 * `flags` is the SCRIPT_VERIFY_* bitfield. Only flags that affect
 * static sigop counting are consulted by the underlying script walker;
 * the legacy counter itself does not gate on any flag — the parameter
 * is forwarded verbatim to script_get_sig_op_count for forward
 * compatibility.
 *
 * On success returns ZCL_OK and writes the count to *out_count.
 * On failure returns one of:
 *   DOMAIN_CONSENSUS_SIGOPS_ERR_NULL_TX   tx == NULL
 *   DOMAIN_CONSENSUS_SIGOPS_ERR_NULL_OUT  out_count == NULL
 *
 * A count of 0 is a legal success result (e.g. a tx whose every script
 * is empty / data-push-only). */
struct zcl_result domain_consensus_tx_legacy_sig_op_count(
        const struct transaction *tx,
        uint32_t flags,
        uint64_t *out_count);

/* Count P2SH sigops contributed by the redeem scripts of every
 * non-coinbase input in `tx`. The caller resolves each input's prevout
 * up front and passes a parallel array `prevouts[]` of length tx->num_vin.
 * A NULL entry means "prevout not found"; that input contributes 0
 * (missing-prevout is reported elsewhere in connect_block).
 *
 * Pure: no IO, no state reads. The whole reason this signature takes a
 * resolved-prevouts array instead of a coins_view_cache is to keep the
 * domain layer independent of the coins-cache adapter.
 *
 * Gating mirrors zclassicd src/main.cpp::GetP2SHSigOpCount:
 *   - SCRIPT_VERIFY_P2SH unset in `flags`  -> count is 0
 *   - tx is coinbase                       -> count is 0
 *   - prevout NULL or non-P2SH             -> input contributes 0
 *
 * The 15-sigop MAX_P2SH_SIGOPS cap is a standardness/policy rule, NOT
 * consensus; we do not apply it here. The total of legacy + P2SH counts
 * is what the MAX_BLOCK_SIGOPS consensus limit is checked against.
 *
 * On success returns ZCL_OK and writes the count to *out_count.
 * On failure returns one of:
 *   DOMAIN_CONSENSUS_SIGOPS_ERR_NULL_TX        tx == NULL
 *   DOMAIN_CONSENSUS_SIGOPS_ERR_NULL_OUT       out_count == NULL
 *   DOMAIN_CONSENSUS_SIGOPS_ERR_NULL_PREVOUTS  prevouts == NULL && tx
 *                                              has non-zero, non-coinbase
 *                                              inputs and SCRIPT_VERIFY_P2SH
 *                                              is set (otherwise the array
 *                                              is unread and may be NULL).
 */
struct zcl_result domain_consensus_tx_p2sh_sig_op_count(
        const struct transaction *tx,
        const struct tx_out *const *prevouts,
        uint32_t flags,
        uint64_t *out_count);

/* Error codes used by domain/consensus/sigops.{c,h}. Stable across
 * builds; new codes are appended. Returned via zcl_result.code. */
enum domain_consensus_sigops_err {
    DOMAIN_CONSENSUS_SIGOPS_ERR_NULL_TX        = 1201,
    DOMAIN_CONSENSUS_SIGOPS_ERR_NULL_OUT       = 1202,
    DOMAIN_CONSENSUS_SIGOPS_ERR_NULL_PREVOUTS  = 1203,
};

#endif /* ZCL_DOMAIN_CONSENSUS_SIGOPS_H */
