/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wallet_scan_service — Pass 2 of the fast wallet block scanner.
 *
 * The wallet_scan Controller (app/controllers/src/wallet_scan.c) parses and
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
#include <stdbool.h>
#include <time.h>

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
 * Returns the number of wallet transactions found, or -1 on error. */
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
