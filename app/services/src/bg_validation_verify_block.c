/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright (c) 2014-2017 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

// one-result-type-ok:read-only-block-verify-predicate
/* E2 override: this TU's surface is a read-only pass/fail block-verification
 * predicate (validate_block_proofs) plus its private undo reader. A failure is
 * reported by the bool + a LOG_WARN naming the height/reject_reason (the whole
 * fail-loud point); a zcl_result would duplicate that channel. Split out of
 * bg_validation_service.c to keep both TUs under the E1 file-size ceiling —
 * behavior is byte-for-byte identical to the original in-service definitions. */

/*
 * bg_validation_verify_block — single-block read-only full validation used by
 * both the genesis→tip walk AND the always-on sampled re-verify loop (see
 * bg_validation_service.c / bg_validation_internal.h). Verifies Equihash + PoW,
 * Merkle root + structure, contextual header, all shielded proofs, and every
 * transparent script signature (recovering spent outputs from undo data). It
 * never modifies the UTXO set.
 */

#include "bg_validation_internal.h"

#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "validation/check_block.h"
#include "validation/contextual_check_tx.h"
#include "validation/sighash.h"
#include "validation/tx_verifier.h"
#include "validation/main_constants.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "storage/disk_block_io.h"
#include "coins/undo.h"
#include "script/interpreter.h"
#include "script/script_flags.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* ── Read undo data for a block ──────────────────────────────── */

/* Maximum bytes to read for a single block's undo data.
 * Typical blocks need <1MB; even dust-attack blocks fit in 4MB.
 * This caps memory per-block without rejecting large rev files. */
#define MAX_UNDO_READ  (4 * 1024 * 1024)

static bool read_block_undo(struct block_undo *undo, const struct block_index *pindex,
                            const char *datadir)
{
    block_undo_init(undo);

    struct disk_block_pos undo_pos = { .nFile = -1, .nPos = 0 };
    if (!block_index_undo_pos_snapshot(pindex, &undo_pos, NULL)) return false; // raw-return-ok:missing-undo-is-counted-as-script-skip

    if (undo_pos.nPos == 0) LOG_FAIL("bg_validation", "read_block_undo: undo pos is 0 for file %d", undo_pos.nFile);

    char path[512];
    get_block_pos_filename(path, sizeof(path), datadir, &undo_pos, "rev");

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        LOG_FAIL("bg_validation", "read_block_undo: cannot open %s", path);

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        LOG_FAIL("bg_validation", "read_block_undo: fstat failed or empty file %s", path);
    }

    /* Read from undo_pos.nPos, capped at MAX_UNDO_READ.
     * The deserializer is stream-based and stops when done — we don't
     * need to read to EOF. This keeps memory bounded per block. */
    size_t avail = (size_t)(st.st_size - (off_t)undo_pos.nPos);
    if (avail == 0) {
        close(fd);
        LOG_FAIL("bg_validation", "read_block_undo: no data available at pos %u in %s",
                 undo_pos.nPos, path);
    }
    size_t read_len = avail < MAX_UNDO_READ ? avail : MAX_UNDO_READ;

    uint8_t *buf = zcl_malloc(read_len, "bg_valid undo buf");
    if (!buf) {
        close(fd);
        LOG_FAIL("bg_validation", "read_block_undo: malloc failed for %zu bytes", read_len);
    }

    ssize_t nread = pread(fd, buf, read_len, (off_t)undo_pos.nPos);
    close(fd);

    if (nread <= 0) {
        free(buf);
        LOG_FAIL("bg_validation", "read_block_undo: pread returned %zd for %s", nread, path);
    }

    struct byte_stream s;
    stream_init_from_data(&s, buf, (size_t)nread);
    bool ok = block_undo_deserialize(undo, &s);
    free(buf);
    return ok;
}

/* ── Single block full validation (read-only) ────────────────── */

/* Validates all cryptographic proofs in a block WITHOUT modifying UTXO set.
 * Verifies: Equihash, Merkle root, all script sigs, all shielded proofs.
 * Uses undo data (revXXXXX.dat) to recover spent outputs for sig verification.
 * max_script_batch: cap on script_check_item allocation (0 = unlimited). */
bool bg_validation_validate_block_proofs(const struct block *block,
                                  struct block_index *pindex,
                                  const char *datadir,
                                  const struct chain_params *params,
                                  int num_workers,
                                  size_t max_script_batch,
                                  int64_t *sigs_out,
                                  int64_t *proofs_out,
                                  int64_t *skips_out)
{
    bool ok = false;
    struct validation_state state;
    validation_state_init(&state);
    int64_t sigs = 0, proofs = 0, skips = 0;
    struct block_undo blockundo;
    bool have_undo = false;
    struct script_check_item *check_items = NULL;
    size_t check_count = 0;

    /* 1. Block header: Equihash + PoW + timestamp */
    if (!check_block_header(&block->header, &state, params, true)) {
        LOG_WARN("bg-valid", "[bg-valid] check_block_header FAILED h=%d: %s",
                pindex->nHeight, state.reject_reason);
        goto out;
    }

    /* 2. Block structure: Merkle root + size limits + tx structure */
    if (!check_block(block, &state, params, true, true, false)) {
        LOG_WARN("bg-valid", "[bg-valid] check_block FAILED h=%d: %s",
                pindex->nHeight, state.reject_reason);
        goto out;
    }

    /* 3. Contextual header: difficulty, median time, checkpoints */
    if (pindex->pprev) {
        if (!contextual_check_block_header(&block->header, &state, params,
                                            pindex->pprev, true)) {
            LOG_WARN("bg-valid", "[bg-valid] contextual_check_header FAILED h=%d: %s",
                    pindex->nHeight, state.reject_reason);
            goto out;
        }
    }

    /* 4. Transaction-level verification */
    uint32_t branch_id = consensus_current_epoch_branch_id(
        pindex->nHeight, &params->consensus);
    uint32_t flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;

    if (block->num_vtx > 1)
        have_undo = read_block_undo(&blockundo, pindex, datadir);

    /* Count transparent inputs and cap allocation */
    size_t total_inputs = 0;
    for (size_t i = 1; i < block->num_vtx; i++)
        total_inputs += block->vtx[i].num_vin;

    size_t alloc_size = total_inputs;
    if (max_script_batch > 0 && alloc_size > max_script_batch)
        alloc_size = max_script_batch;

    if (alloc_size > 0) {
        check_items = zcl_calloc(alloc_size, sizeof(struct script_check_item), "bg_valid script checks");
        if (!check_items)
            goto out;
    }

    for (size_t i = 0; i < block->num_vtx; i++) {
        const struct transaction *tx = &block->vtx[i];

        /* 4a. Shielded proof verification */
        if (tx->num_joinsplit > 0 || tx->num_shielded_spend > 0 ||
            tx->num_shielded_output > 0) {
            if (!bg_validation_verify_shielded_proofs(tx, pindex->nHeight, i,
                                        branch_id, &proofs))
                goto out;
        }

        /* 4b. Collect script verification items */
        if (transaction_is_coinbase(tx))
            continue;

        size_t undo_idx = i - 1;
        bool have_tx_undo = have_undo && undo_idx < blockundo.num_txundo &&
                            blockundo.vtxundo[undo_idx].num_prevout == tx->num_vin;
        if (!have_tx_undo) {
            /* No undo (rev file): cannot recover spent outputs, so this tx
             * CANNOT be script-verified. Expected post-snapshot. Don't stall;
             * record the gap so "verified" stays honest, not a silent skip. */
            skips++;
            continue;
        }

        struct precomputed_tx_data txdata;
        precompute_tx_data(tx, &txdata);

        for (size_t j = 0; j < tx->num_vin; j++) {
            /* Flush batch if at capacity */
            if (max_script_batch > 0 && check_count >= max_script_batch) {
                if (!bg_validation_verify_scripts_parallel(check_items, check_count,
                                              num_workers))
                    goto out;
                check_count = 0;
            }

            const struct tx_out *prev_out =
                &blockundo.vtxundo[undo_idx].vprevout[j].txout;
            struct script_check_item *item = &check_items[check_count++];
            item->tx = tx;
            item->input_index = (unsigned int)j;
            item->amount = prev_out->value;
            item->branch_id = branch_id;
            item->txdata = txdata;
            item->script_pub_key = prev_out->script_pub_key;
            item->flags = flags;
            sigs++;
        }
    }

    /* 5. Final script verification flush */
    if (!bg_validation_verify_scripts_parallel(check_items, check_count, num_workers)) {
        LOG_WARN("bg-valid", "[bg-valid] script verification FAILED h=%d",
                pindex->nHeight);
        goto out;
    }

    if (skips > 0)
        LOG_WARN("bg-valid", "[bg-valid] h=%d: %lld non-coinbase tx(s) NOT "
                "script-verified (undo missing) — block advances, not fully "
                "verified", pindex->nHeight, (long long)skips);

    *sigs_out += sigs;
    *proofs_out += proofs;
    *skips_out += skips;
    ok = true;

out:
    free(check_items);
    if (have_undo)
        block_undo_free(&blockundo);
    return ok;
}
