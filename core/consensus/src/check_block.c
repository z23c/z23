/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure block structural checks. Mirrors the two structural branches of
 * legacy core/modules/validation/check_block.c::check_block_impl():
 *
 *   - check_merkle_root  -> domain_consensus_check_block_merkle_root
 *   - check_size_limits  -> domain_consensus_check_block_size_coinbase_sigops
 *
 * The per-transaction check_transaction() call from the legacy
 * check_size_limits branch is NOT replicated here: it has been
 * extracted into its own domain module (tx_structural) and the lib
 * wrapper continues to invoke it directly.
 *
 * Purity: no clock, no RNG, no I/O, no global state. Internal scratch
 * allocations are freed before return.
 */

#include "domain/consensus/check_block.h"

#include "reject_out.h"

#include "bloom/merkle.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script_flags.h"
#include "util/safe_alloc.h"
#include "domain/consensus/sigops.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Local consensus constants. The legacy code uses a private
 * `GENEROUS_BLOCK_SIZE_LIMIT = 2_000_000` and MAX_BLOCK_SIGOPS = 20_000
 * from validation/main_constants.h / consensus/consensus.h. Both of
 * those headers carry separate macro definitions that conflict at the
 * preprocessor level (suffix differences) — keeping our own constants
 * here lets the domain code avoid the upstream macro tangle entirely
 * while remaining trivially auditable against either source. */
#define DOMAIN_GENEROUS_BLOCK_TXN_LIMIT  ((unsigned int)2000000)
#define DOMAIN_MAX_BLOCK_SIGOPS          ((unsigned int)20000)

/* Flags for the block-level sigop tally. zclassicd counts every top-level
 * OP_CHECKDATASIG / OP_CHECKDATASIGVERIFY toward MAX_BLOCK_SIGOPS — its
 * CheckBlock counts with STANDARD_SCRIPT_VERIFY_FLAGS and its ConnectBlock
 * ORs in SCRIPT_VERIFY_CHECKDATASIG_SIGOPS (zclassic-cpp/src/main.cpp:4006,
 * 2567). For the legacy (non-accurate) count, bit 1<<11 is the ONLY flag
 * that changes the tally, so passing it alone reproduces the reference count
 * exactly while counting each CHECKDATASIG opcode as +1. History-safe:
 * zclassicd already rejected any block whose true sigop total (incl. CHECKDATASIG)
 * exceeds 20000, so the immutable chain contains no block this newly
 * rejects. */
#define DOMAIN_CONSENSUS_SIGOP_COUNT_FLAGS  SCRIPT_VERIFY_CHECKDATASIG_SIGOPS

struct zcl_result domain_consensus_check_block_merkle_root(
        const struct block *block,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos)
{
    if (!block)
        return ZCL_ERR(DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_NULL_ARG,
                       "check_block_merkle_root: null block");

    /* Empty block: legacy compute_merkle_root_mutated(NULL/empty, 0)
     * returns a null hash. We mirror that — no early return; the
     * comparison will produce "bad-txnmrklroot" if the header doesn't
     * also encode null. Size-coinbase-sigops will then catch the
     * "bad-blk-length" rejection. */

    struct uint256 *txids = NULL;
    if (block->num_vtx > 0) {
        txids = zcl_malloc(block->num_vtx * sizeof(struct uint256),
                           "domain_check_block_txids");
        if (!txids) {
            set_reject(out_reject_reason, out_reject_reason_size,
                       "out-of-memory");
            set_dos(out_dos, 0);
            return ZCL_ERR(DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_OUT_OF_MEMORY,
                           "check_block_merkle_root: alloc failed (num_vtx=%zu)",
                           block->num_vtx);
        }
        for (size_t i = 0; i < block->num_vtx; i++)
            txids[i] = block->vtx[i].hash;
    }

    bool mutated = false;
    struct uint256 merkle_root =
            compute_merkle_root_mutated(txids, block->num_vtx, &mutated);
    free(txids);

    if (!uint256_eq(&block->header.hashMerkleRoot, &merkle_root)) {
        set_reject(out_reject_reason, out_reject_reason_size,
                   "bad-txnmrklroot");
        set_dos(out_dos, 100);
        return ZCL_ERR(DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_TXNMRKLROOT,
                       "check_block_merkle_root: bad-txnmrklroot "
                       "(num_vtx=%zu)", block->num_vtx);
    }

    if (mutated) {
        set_reject(out_reject_reason, out_reject_reason_size,
                   "bad-txns-duplicate");
        set_dos(out_dos, 100);
        return ZCL_ERR(DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_TXNS_DUP,
                       "check_block_merkle_root: bad-txns-duplicate "
                       "(num_vtx=%zu)", block->num_vtx);
    }

    set_reject(out_reject_reason, out_reject_reason_size, "");
    set_dos(out_dos, 0);
    return ZCL_OK;
}

struct zcl_result domain_consensus_check_block_size_and_coinbase(
        const struct block *block,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos)
{
    if (!block)
        return ZCL_ERR(DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_NULL_ARG,
                       "check_block_size_and_coinbase: null block");

    /* (1) Txn-count bounds. Upper bound is strict `>` (the limit value
     * itself is permitted; only blocks larger than the limit fail). */
    if (block->num_vtx == 0 ||
        block->num_vtx > DOMAIN_GENEROUS_BLOCK_TXN_LIMIT) {
        set_reject(out_reject_reason, out_reject_reason_size,
                   "bad-blk-length");
        set_dos(out_dos, 100);
        return ZCL_ERR(DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_BLK_LENGTH,
                       "check_block_size_and_coinbase: bad-blk-length "
                       "(num_vtx=%zu)", block->num_vtx);
    }

    /* (2) First tx must be coinbase. */
    if (!transaction_is_coinbase(&block->vtx[0])) {
        set_reject(out_reject_reason, out_reject_reason_size,
                   "bad-cb-missing");
        set_dos(out_dos, 100);
        return ZCL_ERR(DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_CB_MISSING,
                       "check_block_size_and_coinbase: bad-cb-missing");
    }

    /* (3) No other tx may be a coinbase. */
    for (size_t i = 1; i < block->num_vtx; i++) {
        if (transaction_is_coinbase(&block->vtx[i])) {
            set_reject(out_reject_reason, out_reject_reason_size,
                       "bad-cb-multiple");
            set_dos(out_dos, 100);
            return ZCL_ERR(
                    DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_CB_MULTIPLE,
                    "check_block_size_and_coinbase: bad-cb-multiple "
                    "at vtx index %zu", i);
        }
    }

    set_reject(out_reject_reason, out_reject_reason_size, "");
    set_dos(out_dos, 0);
    return ZCL_OK;
}

struct zcl_result domain_consensus_check_block_sigops(
        const struct block *block,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos)
{
    if (!block)
        return ZCL_ERR(DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_NULL_ARG,
                       "check_block_sigops: null block");

    unsigned int n_sig_ops = 0;
    for (size_t i = 0; i < block->num_vtx; i++) {
        /* Call the core sigops predicate directly (validation/sigops.h's
         * get_legacy_sig_op_count is only a thin wrapper over this — see
         * core/modules/validation/src/sigops.c — so this is byte-for-byte identical
         * to the pre-W5 count). The wrapper's fail-safe returned 0 on a null
         * tx; mirror that by contributing 0 on the (unreachable here — vtx[i]
         * is a live struct and out_count is a stack local) error path. */
        uint64_t tx_sig_ops = 0;
        struct zcl_result r = domain_consensus_tx_legacy_sig_op_count(
                &block->vtx[i], DOMAIN_CONSENSUS_SIGOP_COUNT_FLAGS,
                &tx_sig_ops);
        if (r.ok)
            n_sig_ops += (unsigned int)tx_sig_ops;
    }
    if (n_sig_ops > DOMAIN_MAX_BLOCK_SIGOPS) {
        set_reject(out_reject_reason, out_reject_reason_size,
                   "bad-blk-sigops");
        set_dos(out_dos, 100);
        return ZCL_ERR(DOMAIN_CONSENSUS_CHECK_BLOCK_ERR_BAD_BLK_SIGOPS,
                       "check_block_sigops: bad-blk-sigops "
                       "(sigops=%u limit=%u)",
                       n_sig_ops, DOMAIN_MAX_BLOCK_SIGOPS);
    }

    set_reject(out_reject_reason, out_reject_reason_size, "");
    set_dos(out_dos, 0);
    return ZCL_OK;
}
