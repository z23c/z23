/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Declares the fast block-rescan entry point and the Pass-1 file-match cache validity checks.
 */

#ifndef ZCL_DB_WALLET_SCAN_H
#define ZCL_DB_WALLET_SCAN_H

#include "models/database.h"
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

/* Blocks kept below a wallet birthday when scanning, so a short reorganisation
 * of the chain the wallet was created on cannot hide an early payment. */
#define WALLET_SCAN_BIRTHDAY_MARGIN 100

/* First height the initial scan of a wallet made by `core wallet create` may
 * start at: its birthday less the margin, 0 when the wallet has no birthday or
 * when the block recorded at the birthday is no longer the active block at
 * that height (the chain it was created on was replaced). wallet_scan_blocks
 * never applies it: a transparent scan, a rescan and the scan an imported key
 * triggers cover their whole range. Only the boot catch-up of a wallet that has
 * scanned nothing yet uses it. */
int wallet_birthday_scan_floor(struct node_db *ndb);

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
