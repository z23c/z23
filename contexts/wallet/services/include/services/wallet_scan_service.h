/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wallet_scan_service — Pass 2 of the fast wallet block scanner.
 *
 * The wallet_scan Controller (contexts/wallet/controllers/src/wallet_scan.c) parses and
 * validates its arguments and runs Pass 1 (the parallel raw-byte pattern
 * scan over the block files). The orchestration core — Pass 2 — lives here:
 *   - the selective-deserialize block loop (mmap the matched files,
 *     deserialize only the blocks Pass 1 flagged, scan their txns)
 *   - the in-memory UTXO/balance compute
 *   - the SQLite transaction scope (begin / DELETE / save / commit /
 *     rollback) that writes the results.
 *
 * The Controller calls this once and returns its result verbatim. The
 * recovery-primitive callers of wallet_scan_blocks (wallet_rescan_controller,
 * wallet_diagnostic_repair) consume a bare int and are explicitly locked, so
 * this entry deliberately keeps the int contract rather than migrating to
 * struct zcl_result. The service may log internally.
 *
 * Returns the number of wallet transactions found, or -1 on error — the same
 * value the Controller previously computed inline. */

#ifndef ZCL_WALLET_SCAN_SERVICE_H
#define ZCL_WALLET_SCAN_SERVICE_H

#include "models/database.h"
#include "validation/chainstate.h"
#include "services/scan_util.h"
#include "platform/read_mapping.h"
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* Returned instead of -1 when the requested height range holds a height with
 * no block body. Nothing was deleted or written: wallet_utxos and
 * wallet_transactions are exactly as they were. Distinct from -1 (a scan or
 * write failure) so a caller can say which one happened. */
#define WALLET_SCAN_REFUSED_MISSING_DATA (-2)

/* Block-body coverage of one height range on one active chain. */
struct wallet_scan_coverage {
    int start_height;
    int end_height;
    int64_t blocks_missing;   /* heights with no index entry or no body */
    int first_missing;        /* lowest such height, -1 when none */
};

/* True when this active-chain entry has a block body to read. The rule is
 * the one rescanblockchain counts as blocks_missing_data
 * (wallet_scan_one_block in contexts/wallet/modules/wallet/src/
 * wallet_rescan.c): no index entry, or no BLOCK_HAVE_DATA. */
bool wallet_scan_height_has_data(const struct block_index *pi);

/* Count the heights of [start_height, end_height] on `chain` that have no
 * block body, by wallet_scan_height_has_data(). Fills `out` (required) and
 * returns true when none is missing. An empty range (start > end) is
 * complete. A NULL chain counts the whole range as missing. */
bool wallet_scan_range_coverage(const struct active_chain *chain,
                                int start_height, int end_height,
                                struct wallet_scan_coverage *out);

/* Open one canonical block file for mapping without granting write access.
 * The descriptor is close-on-exec (non-inheritable on Windows).
 * Returns a caller-owned descriptor, or -1 on error, including a NULL path. */
int wallet_scan_block_file_open(const char *path);

/* Open and map a nonempty block file through the scan descriptor policy.
 * mapping must be non-NULL and have no live view; it is initialized before
 * any refusal and remains empty on failure. Returns -1 on error, otherwise
 * the caller-owned descriptor, kept open until platform_read_mapping_close(). */
int wallet_scan_block_file_map(const char *path,
                               struct platform_read_mapping *mapping);

/* Run Pass 2 of the wallet block scan.
 *
 * ndb:            our SQLite database for storing results (must be open)
 * chain:          active chain index (file locations per height)
 * datadir:        data directory (blocks/blk%05d.dat live here)
 * start_height:   first height to deserialize (inclusive)
 * end_height:     last height to deserialize (inclusive)
 * aht:            address hash table built by Pass 1 (caller-owned)
 * file_has_match: per-file Pass-1 match flags (caller-owned)
 * matched_files:  number of true entries; zero preserves the O(1) empty
 *                 replacement path without a chain-height walk
 * ts_start:       monotonic timestamp captured before Pass 1 (for totals)
 * ts_p1:          monotonic timestamp captured after Pass 1
 *
 * When matched_files > 0, Pass 2 rereads every height of the range before it
 * writes anything; a height with no block body ends the scan with
 * WALLET_SCAN_REFUSED_MISSING_DATA and no row is touched.
 *
 * Returns the number of wallet transactions found, -1 on error, or
 * WALLET_SCAN_REFUSED_MISSING_DATA. */
int wallet_scan_pass2_execute(struct node_db *ndb,
                              const struct active_chain *chain,
                              const char *datadir,
                              int start_height,
                              int end_height,
                              const struct scan_addr_ht *aht,
                              const bool *file_has_match,
                              int matched_files,
                              const struct timespec *ts_start,
                              const struct timespec *ts_p1);

#endif /* ZCL_WALLET_SCAN_SERVICE_H */
