/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Wallet rescan: walk a height range, fold each block's transactions into
 * the wallet, and account for what was actually READ versus merely visited.
 *
 * Split out of wallet.c because the coverage accounting here is a concern of
 * its own. A rescan's "found N" is only meaningful alongside how much of the
 * range the node could actually open: wallet_scan_block() historically
 * returned a bare 0 both for "this block holds nothing of yours" and for
 * "this node has no body for that block", which let a rescan over a
 * body-less range (the snapshot-bootstrap state) report zero found and look
 * like a definitive answer. Everything below keeps those two apart. */

#include "wallet/wallet.h"
#include "util/log_macros.h"
#include "core/utiltime.h"
#include "storage/disk_block_io.h"
#include "validation/chainstate.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/* One block's contribution to a rescan. `r` is optional; when present every
 * outcome — including the two distinct ways a block yields nothing — is
 * counted into it. Returns outputs + notes found in this block. */
static int wallet_scan_one_block(struct wallet *w,
                                 const struct block_index *pindex,
                                 const char *datadir,
                                 struct wallet_rescan_report *r)
{
    /* The block is indexed but the node holds no body for it. This is NOT
     * "nothing of yours is here" — nothing was looked at. Count it apart. */
    if (!pindex || !(pindex->nStatus & BLOCK_HAVE_DATA)) {
        if (r) r->blocks_missing_data++;
        return 0;
    }

    struct block b;
    block_init(&b);
    if (!read_block_from_disk_index(&b, pindex, datadir)) {
        /* Body claimed present but unreadable — a truncated or missing
         * block file. Also not evidence of absence. */
        if (r) r->blocks_read_failed++;
        block_free(&b);
        return 0;
    }

    if (r) r->blocks_scanned++;

    int found = 0;
    for (size_t i = 0; i < b.num_vtx; i++) {
        wallet_sync_transaction(w, &b.vtx[i], pindex);
        for (size_t j = 0; j < b.vtx[i].num_vout; j++) {
            if (wallet_is_mine(w, &b.vtx[i].vout[j])) {
                found++;
                if (r) r->outputs_found++;
            }
        }
        /* Trial-decrypt Sapling outputs */
        if (b.vtx[i].num_shielded_output > 0) {
            if (w->sapling_keys.num_keys > 0) {
                struct uint256 txid;
                transaction_compute_hash((struct transaction *)&b.vtx[i]);
                txid = b.vtx[i].hash;
                int z_found = wallet_try_sapling_decrypt(w, &b.vtx[i], &txid);
                found += z_found;
                if (r) r->shielded_notes_found += z_found;
            } else if (r) {
                /* No Sapling key: these outputs were never even tried. The
                 * seed-only-restore state. Record it instead of silently
                 * skipping — a caller that reports "0 found" here is
                 * reporting the absence of a search, not of funds. */
                r->shielded_txs_unscanned++;
            }
        }
        /* Mark spent nullifiers */
        if (b.vtx[i].num_shielded_spend > 0)
            wallet_mark_sapling_nullifiers_spent(w, &b.vtx[i]);
    }

    block_free(&b);
    return found;
}

int wallet_scan_block(struct wallet *w, const struct block_index *pindex,
                      const char *datadir)
{
    return wallet_scan_one_block(w, pindex, datadir, NULL);
}

/* Decide whether this rescan's yield is trustworthy, and if not, name why.
 * Ladder is most-severe first; each name is stable and actionable. */
static void wallet_rescan_classify(struct wallet_rescan_report *r)
{
    r->blocker[0] = '\0';
    r->coverage_ok = true;
    r->shielded_scan_skipped = (r->shielded_txs_unscanned > 0 &&
                                r->sapling_key_count == 0);

    int64_t unread = r->blocks_missing_data + r->blocks_read_failed;
    int64_t found  = r->outputs_found + r->shielded_notes_found;

    if (unread <= 0)
        return;  /* every indexed height in range was actually read */

    const char *name = NULL;
    if (r->blocks_indexed > 0 && r->blocks_scanned == 0) {
        /* Not one body in the whole range. A snapshot-bootstrapped node
         * asked to rescan: the answer carries no information at all. */
        name = WALLET_RESCAN_BLOCKER_NO_BLOCK_DATA;
    } else if (r->blocks_indexed > 0 &&
               (r->blocks_scanned * 100) / r->blocks_indexed
                   < WALLET_RESCAN_MIN_COVERAGE_PCT) {
        name = WALLET_RESCAN_BLOCKER_INCOMPLETE;
    } else if (found == 0) {
        /* Coverage is high but not total AND we found nothing. We cannot
         * distinguish "you have no funds" from "your funds are in one of
         * the blocks we could not read." Refuse to imply the former. */
        name = WALLET_RESCAN_BLOCKER_INCONCLUSIVE;
    }

    if (name) {
        r->coverage_ok = false;
        snprintf(r->blocker, sizeof(r->blocker), "%s", name);
    }
}

int wallet_rescan_report(struct wallet *w, const struct active_chain *chain,
                         int start_height, int stop_height,
                         const char *datadir,
                         struct wallet_rescan_report *out)
{
    struct wallet_rescan_report local;
    struct wallet_rescan_report *r = out ? out : &local;
    memset(r, 0, sizeof(*r));
    r->coverage_ok = true;

    if (!w || !chain) {
        r->coverage_ok = false;
        snprintf(r->blocker, sizeof(r->blocker), "RESCAN_NO_WALLET");
        /* LOG_ERR returns -1 — which it must, since every line below
         * dereferences both `w` and `chain`. */
        LOG_ERR("wallet", "rescan called with %s NULL",
                !w ? "wallet" : "chain");
    }

    int tip = active_chain_height(chain);
    if (stop_height < 0 || stop_height > tip)
        stop_height = tip;
    if (start_height < 0)
        start_height = 0;

    r->start_height = start_height;
    r->stop_height = stop_height;
    r->sapling_key_count = w->sapling_keys.num_keys;

    if (start_height > stop_height)
        return 0;

    r->blocks_in_range = (int64_t)stop_height - start_height + 1;

    LOG_INFO("wallet", "Rescanning blocks %d to %d...", start_height, stop_height);
    int64_t t_start = GetTime();
    int total_found = 0;
    int last_log = start_height;

    /* Set best_block_height to stop_height before scanning so that
     * wallet_sync_transaction computes correct confirmation depth. */
    w->best_block_height = stop_height;

    for (int h = start_height; h <= stop_height; h++) {
        struct block_index *pindex = active_chain_at(chain, h);
        if (!pindex) {
            r->blocks_no_index++;
            continue;
        }
        r->blocks_indexed++;

        total_found += wallet_scan_one_block(w, pindex, datadir, r);

        if (h - last_log >= 10000) {
            LOG_INFO("wallet", "rescan progress: height %d / %d (%.1f%%)",
                     h, stop_height,
                     100.0 * (h - start_height) / (stop_height - start_height + 1));
            last_log = h;
        }
    }

    struct block_index *final_tip = active_chain_at(chain, stop_height);
    if (final_tip) {
        w->best_block = final_tip;
        w->best_block_height = stop_height;
    }

    wallet_rescan_classify(r);

    int64_t elapsed = GetTime() - t_start;
    LOG_INFO("wallet",
             "Rescan complete: %d..%d, %"PRId64" of %"PRId64" indexed blocks read "
             "in %"PRId64"s, %"PRId64" outputs + %"PRId64" shielded notes found "
             "(%"PRId64" missing body, %"PRId64" unreadable, %"PRId64" unindexed).",
             start_height, stop_height, r->blocks_scanned, r->blocks_indexed,
             elapsed, r->outputs_found, r->shielded_notes_found,
             r->blocks_missing_data, r->blocks_read_failed, r->blocks_no_index);

    if (r->shielded_scan_skipped)
        LOG_WARN("wallet",
                 "Rescan left %"PRId64" shielded transaction(s) untried: the wallet "
                 "holds no Sapling key. Any shielded funds in %d..%d were NOT "
                 "searched for — import the Sapling key, then rescan again.",
                 r->shielded_txs_unscanned, start_height, stop_height);

    if (!r->coverage_ok)
        LOG_ERROR("wallet",
                  "%s: rescan of %d..%d read only %"PRId64" of %"PRId64" indexed "
                  "blocks (%"PRId64" have no block body on this node). The result "
                  "(%"PRId64" outputs, %"PRId64" notes) does NOT mean the wallet is "
                  "empty — this node cannot see those blocks' transactions.",
                  r->blocker, start_height, stop_height, r->blocks_scanned,
                  r->blocks_indexed, r->blocks_missing_data + r->blocks_read_failed,
                  r->outputs_found, r->shielded_notes_found);

    return total_found;
}

int wallet_rescan(struct wallet *w, const struct active_chain *chain,
                  int start_height, int stop_height, const char *datadir)
{
    return wallet_rescan_report(w, chain, start_height, stop_height,
                                datadir, NULL);
}

