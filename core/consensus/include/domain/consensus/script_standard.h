/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * domain/consensus/script_standard.h — pure standard-script-type detection.
 *
 * Recognises the five "standard" output-script shapes (P2PKH, P2PK,
 * P2SH, multisig, OP_RETURN) and the corresponding destination
 * extraction. Each function is a static walk over script bytes; the
 * result depends only on the script + (where present) pubkey arithmetic.
 *
 * No clock, no RNG, no I/O, no state reads. Replays from inputs alone.
 *
 * Layering: domain/consensus/ may #include from util/, core/, chain/,
 * consensus/, crypto/, sapling/, script/, primitives/, keys/. The fact
 * these functions depend only on script/script.h and keys/pubkey.h
 * (both pure) is what makes them eligible to live here.
 *
 * Background: zclassicd src/script/standard.cpp::Solver +
 * ExtractDestination are the historic source-of-truth. The set of
 * recognised tx_out types here pins the explorer / wallet view layer
 * and the standardness gate in the mempool admission path.
 *
 * The core/modules/script/standard.{c,h} module is a thin signature-preserving
 * wrapper around these functions; existing callers (wallet, explorer,
 * controllers) are unchanged.
 */

#ifndef ZCL_DOMAIN_CONSENSUS_SCRIPT_STANDARD_H
#define ZCL_DOMAIN_CONSENSUS_SCRIPT_STANDARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util/result.h"

struct script;
struct pubkey;
struct key_id;
struct script_id;
struct tx_destination;

/* Standard tx_out type tags. Matches core/modules/script/standard.h::txnouttype
 * verbatim — the typed alias exists so the domain layer is the source
 * of truth and the lib wrapper just typedefs to it. */
enum domain_script_txnouttype {
    DOMAIN_SCRIPT_TX_NONSTANDARD = 0,
    DOMAIN_SCRIPT_TX_PUBKEY,
    DOMAIN_SCRIPT_TX_PUBKEYHASH,
    DOMAIN_SCRIPT_TX_SCRIPTHASH,
    DOMAIN_SCRIPT_TX_MULTISIG,
    DOMAIN_SCRIPT_TX_NULL_DATA,
};

/* Human-readable name for a standard tx_out type. NULL on
 * out-of-range input — matches zclassicd's GetTxnOutputType. */
const char *domain_consensus_script_txn_output_type_name(
        enum domain_script_txnouttype t);

/* Match `s` against the standard-script template patterns and (on a
 * match) extract the solution slots. `solutions` is a caller-owned
 * 2D buffer of at least `solutions_cap` rows × 65 bytes; `solution_sizes`
 * is a parallel length-array of the same row count. `num_solutions`
 * receives the number of slots actually written. The 65-byte row width
 * matches the legacy contract and is wide enough for an uncompressed
 * pubkey + the multisig M/N count bytes.
 *
 * Returns ZCL_OK on success (including NONSTANDARD with no match), and
 * sets *type_out + *matched + *num_solutions appropriately. On match
 * *matched is true and *num_solutions reflects the pattern (1 for
 * P2PKH/P2PK/P2SH, 0 for NULL_DATA, N+2 for an M-of-N multisig).
 *
 * Multisig overflow: if the script declares more keys than the
 * caller's `solutions_cap` can hold, *matched is false (graceful
 * fallback to NONSTANDARD) — a domain function never writes out of
 * bounds. The lib wrapper passes a 20-row buffer which fits the
 * 16-key MAX_PUBKEYS_PER_MULTISIG cap.
 *
 * Error codes:
 *   DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_SCRIPT     s == NULL
 *   DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_OUT        any out pointer NULL
 *   DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_SOLUTIONS  solutions buffer NULL
 *                                                       (or sizes NULL)
 */
struct zcl_result domain_consensus_script_solver(
        const struct script *s,
        unsigned char solutions[][65],
        size_t solution_sizes[],
        size_t solutions_cap,
        enum domain_script_txnouttype *type_out,
        size_t *num_solutions,
        bool *matched);

/* Number of stack items expected in the scriptSig that satisfies a
 * scriptPubKey of the given type. Mirrors zclassicd
 * standard.cpp::Solver's per-type spend witness arity:
 *   PUBKEY      -> 1   (signature)
 *   PUBKEYHASH  -> 2   (sig + pubkey)
 *   SCRIPTHASH  -> 1   (redeem-script push; serialised separately)
 *   MULTISIG    -> M+1 (one extra dummy for the well-known off-by-one)
 *   NONSTANDARD,
 *   NULL_DATA   -> -1  (un-spendable / un-signed)
 *
 * Returns -1 on bad-argument (caller fed a multisig type with no
 * solutions[] row 0 carrying the M-count byte). Errors are reported
 * via the -1 sentinel rather than zcl_result — the legacy lib API
 * is bool/int and we preserve it. */
int domain_consensus_script_sig_args_expected(
        enum domain_script_txnouttype t,
        const unsigned char solutions[][65],
        const size_t solution_sizes[],
        size_t num_solutions);

/* Extract a single destination (key_id for P2PKH/P2PK, script_id for
 * P2SH) from a standard scriptPubKey. Multisig and NULL_DATA don't
 * map to a single destination — returns ZCL_OK with *matched=false.
 *
 * The dest_out pointer is required (non-NULL). For P2PK, the pubkey
 * must be valid (curve-point check); an invalid pubkey returns
 * *matched=false with dest_out->type set to DEST_NONE (the rest of
 * dest_out is left unspecified — callers must not read it when
 * *matched is false). */
struct zcl_result domain_consensus_script_extract_destination(
        const struct script *s,
        struct tx_destination *dest_out,
        bool *matched);

/* Compute the RIPEMD160(SHA256(s)) script-hash used to wrap a redeem
 * script into a P2SH scriptPubKey. Pure. Caller owns out_hash[20]. */
struct zcl_result domain_consensus_script_id_from_script(
        const struct script *s,
        unsigned char out_hash[20]);

/* Error codes for domain/consensus/script_standard.{c,h}. Stable
 * across builds; new codes appended. Returned via zcl_result.code. */
enum domain_consensus_script_standard_err {
    DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_SCRIPT    = 1401,
    DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_OUT       = 1402,
    DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_SOLUTIONS = 1403,
};

#endif /* ZCL_DOMAIN_CONSENSUS_SCRIPT_STANDARD_H */
