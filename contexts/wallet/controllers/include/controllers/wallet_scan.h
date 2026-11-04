/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Declares the fast block-rescan entry point and the Pass-1 file-match cache validity checks.
 */

#ifndef ZCL_DB_WALLET_SCAN_H
#define ZCL_DB_WALLET_SCAN_H

#include "models/database.h"
#include "models/wallet_key.h"
#include "validation/chainstate.h"
#include <stdbool.h>
#include <stdint.h>

struct wallet;

/* Fast wallet rescan using pre-built chain index.
 *
 * Scans blocks from start_height to end_height, using the active chain's
 * block_index entries for file locations. Finds wallet transactions using
 * a hash table of address hashes (O(1) lookup vs O(n) keystore scan).
 * Tracks UTXOs in memory and bulk-writes results to SQLite.
 *
 * Returns the number of wallet transactions found, or -1 on error. */
int wallet_scan_blocks(struct node_db *ndb,
                       const struct active_chain *chain,
                       const struct wallet *w,
                       const char *datadir,
                       int start_height,
                       int end_height);

/* Blocks kept below a wallet birthday, so a short reorganisation of the chain
 * the wallet was created on cannot hide an early payment. */
#define WALLET_SCAN_BIRTHDAY_MARGIN WALLET_BIRTHDAY_MARGIN

/* What the active chain says about a wallet's birthday:
 *   NONE    no birthday (old or restored wallet): scan from genesis. On a chain
 *           above 1000 blocks the first boot catch-up defers that scan, and a
 *           restored wallet carries a pending retry until a rescan reads it.
 *   VALID   the active chain holds the recorded floor block; `*floor` is its
 *           height and the first scan may start there.
 *   AHEAD   the active chain has a tip below the floor height (a node still
 *           syncing toward a birthday set from its anchor or headers, or one
 *           rewound below it); `*floor` is that height. The first scan starts
 *           there only after the floor block is verified. Until then coverage
 *           remains unread and the catch-up walk cannot skip the prefix. A
 *           matching floor starts a pending scan from that floor.
 *   CHANGED a birthday exists but the active chain does not hold the floor
 *           block (another block at its height, or no chain loaded): nothing
 *           about the blocks below it can be assumed, the scan is from
 *           genesis.
 * wallet_scan_blocks never applies the floor: a transparent scan, a rescan and
 * the scan an imported key triggers cover their whole range. Only the boot
 * catch-up of a wallet that has scanned nothing yet uses it. */
enum wallet_birthday_state {
    WALLET_BIRTHDAY_NONE,
    WALLET_BIRTHDAY_VALID,
    WALLET_BIRTHDAY_AHEAD,
    WALLET_BIRTHDAY_CHANGED,
};
enum wallet_birthday_state wallet_birthday_check(
    struct node_db *ndb, const struct active_chain *chain, int *floor);

void wallet_birthday_reconcile(struct wallet *w, struct node_db *ndb,
                               struct active_chain *chain,
                               const struct block_index *reached);

/* OS-S2 #4 Pass-1 file-match cache (exposed for unit tests). */

/* FNV-1a fold over every live key/script id + counts. Deterministic for a
 * fixed keyset; changes whenever a key/script is added or removed. */
uint64_t wallet_scan_keyset_fp(const struct wallet *w);

/* True iff a persisted Pass-1 cache with (cached_fp, cached_tip) may be reused
 * against the current (cur_fp, cur_tip): keyset unchanged and the tip has not
 * rewound below the cached height (a reorg). Per-file size equality is checked
 * separately by the caller. */
bool wallet_scan_cache_valid(uint64_t cached_fp, uint64_t cur_fp,
                             int cached_tip, int cur_tip);

#endif
