/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot wallet catch-up: rescan the heights the wallet missed while the node
 * was down, before the wallet serves spends. A rescan that cannot read its
 * range leaves a pending retry instead of recording the range as scanned. */

#include "config/boot_internal.h"
#include "controllers/wallet_scan.h"
#include "wallet/wallet.h"
#include "validation/chainstate.h"
#include "util/log_macros.h"
#include "util/util.h"
#include "core/utiltime.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* First height the boot catch-up scans, or -1 when it must not run. A retry
 * left pending by an earlier catch-up lowers the start and runs even when the
 * wallet is level with the tip. A wallet ahead of the tip never rescans: the
 * rescan would lower the height every stored depth is measured from. */
static int boot_wallet_catch_up_start(const struct wallet *w,
                                      const struct active_chain *chain,
                                      int tip_height)
{
    if (!active_chain_tip(chain) || w->best_block_height > tip_height)
        return -1;
    if (!w->scan_retry.pending && w->best_block_height >= tip_height)
        return -1;
    int scan_from = w->best_block_height > 0 ? w->best_block_height + 1 : 0;
    /* A wallet that has scanned nothing starts at its verified birthday floor;
     * a pending retry below it still wins. */
    if (scan_from == 0 && w->initial_scan_floor > 0)
        scan_from = w->initial_scan_floor;
    if (w->scan_retry.pending && w->scan_retry.from < scan_from)
        scan_from = w->scan_retry.from > 0 ? w->scan_retry.from : 0;
    /* A pending range that starts above this tip cannot be read yet. */
    return scan_from > tip_height ? -1 : scan_from;
}

/* Record what the catch-up proved. best_block_height stays at the stop
 * height either way: wallet_rescan_report measured every found output's depth
 * from it, and wallet_advance_confirmations adds each later tip's distance
 * from it, so lowering it would overstate those depths. What a short read
 * must not do is let the wallet, or its next flush, claim it scanned the
 * range. scan_retry keeps the lowest unread start, the blocker and when it was
 * first seen; the flush persists the scanned-through height and that marker
 * in the same transaction as the tx rows, and the next boot rescans from it. */
static void boot_wallet_catch_up_settle(struct wallet *w,
                                        const struct wallet_rescan_report *r)
{
    /* Only a read of every body clears the marker. coverage_ok tolerates
     * a 1% short read once coins are found, and an unread block can still
     * hold one. */
    bool read_all = r->blocks_scanned == r->blocks_in_range;
    const char *blocker = r->blocker[0] ? r->blocker
                                        : WALLET_RESCAN_BLOCKER_INCOMPLETE;
    zcl_mutex_lock(&w->cs);
    if (read_all && w->scan_retry.pending &&
        (r->shielded_txs_unscanned > 0 || w->sapling_keys.num_unscannable > 0)) {
        /* Every body was read but some Sapling outputs were never tried for
         * want of a key, or a stored key cannot scan while the wallet is
         * locked: an existing marker must wait for a read that tried them. */
        zcl_mutex_unlock(&w->cs);
        return;
    }
    if (read_all && w->scan_retry.pending &&
        r->start_height > w->scan_retry.from) {
        zcl_mutex_unlock(&w->cs);
        return;
    }
    if (read_all) {
        if (w->scan_retry.pending &&
            strcmp(w->scan_retry.blocker, WALLET_BIRTHDAY_PENDING) == 0)
            w->initial_scan_floor = 0;
        memset(&w->scan_retry, 0, sizeof(w->scan_retry));
        zcl_mutex_unlock(&w->cs);
        return;
    }
    int from = r->start_height;
    if (w->scan_retry.pending && w->scan_retry.from < from)
        from = w->scan_retry.from;
    if (!w->scan_retry.pending)
        w->scan_retry.since = GetTime();
    w->scan_retry.pending = true;
    w->scan_retry.from = from;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s",
             blocker);
    zcl_mutex_unlock(&w->cs);
    LOG_WARN("wallet",
             "%s: boot catch-up read %" PRId64 " of %" PRId64 " blocks in "
             "%d..%d (%" PRId64 " without a body, %" PRId64 " unreadable); "
             "wallet scanned through %d only, next boot rescans from %d",
             blocker, r->blocks_scanned, r->blocks_in_range,
             r->start_height, r->stop_height, r->blocks_missing_data,
             r->blocks_read_failed, from - 1, from);
}

#define BOOT_DEFERRED_BLOCKER "WALLET_CATCH_UP_DEFERRED"

/* A first catch-up that defers leaves a wallet that has scanned nothing
 * (best_block_height 0) with no record of the unread range, and the next tip
 * would set its height over the gap. Mark the range from `from` unread, so the
 * wallet reads incomplete until a rescan reads it. A marker already pending
 * stays. */
static void boot_wallet_defer_unread(struct wallet *w, int from)
{
    if (w->best_block_height != 0)
        return;
    zcl_mutex_lock(&w->cs);
    if (!w->scan_retry.pending) {
        w->scan_retry.pending = true;
        w->scan_retry.from = from;
        w->scan_retry.since = GetTime();
        snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s",
                 BOOT_DEFERRED_BLOCKER);
    }
    zcl_mutex_unlock(&w->cs);
}

int boot_wallet_catch_up(struct wallet *w, const struct active_chain *chain,
                         const char *datadir,
                         struct wallet_rescan_report *report)
{
    int tip_height = active_chain_height(chain);
    int scan_from = boot_wallet_catch_up_start(w, chain, tip_height);
    if (scan_from < 0)
        return -1;
    int64_t scan_time = w->time_first_key - 7200;
    for (int h = tip_height;
         w->time_first_key > 0 && !w->scan_retry.pending && scan_from == 0 && h >= 0; h--) {
        struct block_index *bi = active_chain_at(chain, h);
        if (bi && (int64_t)bi->nTime < scan_time)
            scan_from = h + 1;
    }
    if (scan_from == 0 && w->best_block_height == 0 && tip_height > 1000) {
        printf("Wallet scan height is 0 with %d blocks. Use rescanblockchain "
               "RPC for targeted rescan.\n", tip_height);
        boot_wallet_defer_unread(w, scan_from);
        return -1;
    }
    if (tip_height - scan_from >= 50000) {
        printf("Wallet needs rescan from %d to %d (%d blocks). "
               "Deferring — use rescanblockchain RPC.\n",
               scan_from, tip_height, tip_height - scan_from);
        boot_wallet_defer_unread(w, scan_from);
        return -1;
    }
    /* Bodies live under the network directory (<base>/regtest on regtest,
     * the base on mainnet); reading <base> there fails every body. */
    char body_root[4096];
    GetDataDir(true, body_root, sizeof(body_root));
    struct wallet_rescan_report local;
    struct wallet_rescan_report *r = report ? report : &local;
    int found = wallet_rescan_report(w, chain, scan_from, tip_height,
                                     body_root[0] ? body_root : datadir, r);
    boot_wallet_catch_up_settle(w, r);
    return found;
}

#define BOOT_BIRTHDAY_CHANGED_BLOCKER WALLET_BIRTHDAY_CHANGED_BLOCKER

/* The chain the wallet was made on no longer holds its floor block, so nothing
 * below it can be assumed. Mark the whole chain unread: until a catch-up reads
 * it the wallet claims no scanned-through height, so a tip that advances over
 * the gap cannot stand in for the blocks never read. */
static void boot_wallet_birthday_changed(struct wallet *w)
{
    zcl_mutex_lock(&w->cs);
    if (!w->scan_retry.pending)
        w->scan_retry.since = GetTime();
    w->scan_retry.pending = true;
    w->scan_retry.from = 0;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s",
             BOOT_BIRTHDAY_CHANGED_BLOCKER);
    zcl_mutex_unlock(&w->cs);
    LOG_WARN("wallet", "%s: the active chain does not hold this wallet's "
             "birthday block; the whole chain is rescanned, not just the "
             "range above it", BOOT_BIRTHDAY_CHANGED_BLOCKER);
}

static bool boot_wallet_birthday_await(struct wallet *w, const struct active_chain *chain,
                                       struct node_db *ndb, int *floor)
{
    enum wallet_birthday_state st = wallet_birthday_check(ndb, chain, floor);
    if (st == WALLET_BIRTHDAY_AHEAD || st == WALLET_BIRTHDAY_VALID)
        w->initial_scan_floor = *floor;
    wallet_birthday_reconcile(w, ndb, (struct active_chain *)chain,
                              active_chain_tip(chain));
    return w->scan_retry.pending &&
        strcmp(w->scan_retry.blocker, WALLET_BIRTHDAY_PENDING) == 0;
}

int boot_wallet_boot_catch_up(struct wallet *w, const struct active_chain *chain,
                              const char *datadir, struct node_db *ndb)
{
    int floor = 0;
    bool awaiting = w->scan_retry.pending &&
        strcmp(w->scan_retry.blocker, WALLET_BIRTHDAY_PENDING) == 0;
    w->initial_scan_floor = 0;
    if (awaiting) {
        if (boot_wallet_birthday_await(w, chain, ndb, &floor))
            return -1;
    } else if (w->scan_retry.pending || w->best_block_height > 0) {
        enum wallet_birthday_state st = wallet_birthday_check(ndb, chain, &floor);
        if (st == WALLET_BIRTHDAY_VALID)
            w->initial_scan_floor = floor;
        else if (st == WALLET_BIRTHDAY_CHANGED || st == WALLET_BIRTHDAY_AHEAD)
            boot_wallet_birthday_changed(w);
    } else if (w->best_block_height == 0 && !w->scan_retry.pending) {
        enum wallet_birthday_state st = wallet_birthday_check(ndb, chain,
                                                              &floor);
        /* AHEAD keeps the floor too: the catch-up start is then above the
         * tip, so nothing runs until the chain reaches the floor. */
        bool held = st == WALLET_BIRTHDAY_VALID || st == WALLET_BIRTHDAY_AHEAD;
        w->initial_scan_floor = held ? floor : 0;
        if (st == WALLET_BIRTHDAY_CHANGED)
            boot_wallet_birthday_changed(w);
        if (st == WALLET_BIRTHDAY_AHEAD) {
            zcl_mutex_lock(&w->cs);
            w->scan_retry.pending = true;
            w->scan_retry.from = 0;
            w->scan_retry.since = GetTime();
            snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker),
                     "%s", WALLET_BIRTHDAY_PENDING);
            zcl_mutex_unlock(&w->cs);
            return -1;
        }
    }
    return boot_wallet_catch_up(w, chain, datadir, NULL);
}
