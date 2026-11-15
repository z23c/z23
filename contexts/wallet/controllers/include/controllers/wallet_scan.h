/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Declares the fast block-rescan entry point and the Pass-1 file-match cache validity checks.
 */

#ifndef ZCL_DB_WALLET_SCAN_H
#define ZCL_DB_WALLET_SCAN_H

#include "models/database.h"
#include "models/wallet_key.h"
#include "services/wallet_scan_service.h"
#include "validation/chainstate.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

struct wallet;

/* Fast wallet rescan using pre-built chain index.
 *
 * Scans blocks from start_height to end_height, using the active chain's
 * block_index entries for file locations. Finds wallet transactions using
 * a hash table of address hashes (O(1) lookup vs O(n) keystore scan).
 * Tracks UTXOs in memory and replaces wallet_utxos and wallet_transactions
 * with what it found, in one SQLite transaction.
 *
 * Coverage guard: before Pass 1 reads a file or any row is deleted, every
 * height of [start_height, end_height] must hold a block body
 * (wallet_scan_range_coverage). If one does not, the scan returns
 * WALLET_SCAN_REFUSED_MISSING_DATA and leaves both tables untouched, so a
 * node started from a state bundle (no bodies below the bundle height) can
 * never replace the rows with a result read from a range with holes. Pass 2
 * rechecks every height before it writes. The empty-range path, and the
 * no-keys path of a wallet with no watch-only address, read no block and
 * skip the guard; a wallet whose only ids are watch-only (the scan loads
 * none of them) passes the guard before its empty replace.
 *
 * Returns the number of wallet transactions found, -1 on error, or
 * WALLET_SCAN_REFUSED_MISSING_DATA. */
int wallet_scan_blocks(struct node_db *ndb,
                       const struct active_chain *chain,
                       const struct wallet *w,
                       const char *datadir,
                       int start_height,
                       int end_height);

/* wallet_scan_blocks, and fills `coverage` (optional) with what the coverage
 * guard counted: the missing-block count and first missing height that a
 * refusal reports. On a path that skips the guard it reports the range with
 * nothing missing. */
int wallet_scan_blocks_checked(struct node_db *ndb,
                               const struct active_chain *chain,
                               const struct wallet *w,
                               const char *datadir,
                               int start_height,
                               int end_height,
                               struct wallet_scan_coverage *coverage);

/* The way out of a refusal that exists on such a node: the below-tip body
 * backfill (engine/services/src/body_backfill_service.c) fetches the missing
 * bodies unless it was turned off. */
#define WALLET_SCAN_MISSING_DATA_WAY_OUT \
    "This node fetches missing blocks in the background unless it runs " \
    "with -bodyhistorybackfill=off (-bodyhistorybackfill=normal fetches " \
    "them faster)."

/* The refusal body for a row-replacing command (rescanwallet, reindexdb,
 * replaywalletfromchain) whose range lacks block bodies: the missing count,
 * the first missing height, that the wallet rows were kept, and the way out.
 * Writes at most cap bytes, always NUL-terminated when cap > 0. */
void wallet_scan_refusal_text(const char *command,
                              const struct wallet_scan_coverage *coverage,
                              char *out, size_t cap);

/* The tip a row-replacing command (rescanwallet, reindexdb,
 * replaywalletfromchain) scans 0..tip to. False, with a refusal body in out,
 * when the active chain has no tip: the range 0..-1 would take the empty-range
 * path and replace the rows with nothing. */
bool wallet_scan_tip_for_replace(const struct active_chain *chain,
                                 const char *command, int *tip,
                                 char *out, size_t cap);

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
 *   UNAVAILABLE the floor cannot be checked because its active-chain slot
 *           or hash is missing. Keep the birthday pending; do not skip history.
 *   CHANGED a birthday is malformed or a different floor block is present: nothing
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
    WALLET_BIRTHDAY_UNAVAILABLE,
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
