/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * replay_verify_service — offline integrity / PoW verification sweep over
 * the legacy on-disk block log.
 *
 * This re-derives the four cheap consensus invariants directly from zclassicd's
 * persisted block storage, with no dependence on the live node's in-memory
 * chainstate. Given a datadir, it opens the read-only block_log_legacy
 * adapter (block_log_port.iter_from) and, for each block from
 * start_height up to (start_height + max_blocks - 1, or tip), verifies:
 *
 *   1. The Equihash solution against the block's persisted nSolution, at
 *      the (N,K) consensus selects for that block's height.
 *   2. The block-header hash meets the difficulty target encoded in nBits.
 *   3. prev-block linkage is contiguous (each block's hashPrevBlock equals
 *      the hash of the previously iterated block).
 *   4. The merkle root in the header matches the block's transactions.
 *
 * Checks (1), (2) and (4) are delegated to the canonical consensus helper
 * check_block(check_pow=true, check_merkle_root=true); the crypto is NOT
 * reimplemented here. Check (3) is computed at the sweep level because the
 * block_log adapter hands blocks back in active-chain order but does not
 * itself assert linkage.
 *
 * It is read-only and side-effect free apart from a one-line artifact-style
 * summary emitted to the log. It does NOT touch the live node, any service,
 * or any systemd unit.
 */

#ifndef ZCL_SERVICES_REPLAY_VERIFY_SERVICE_H
#define ZCL_SERVICES_REPLAY_VERIFY_SERVICE_H

#include "util/result.h"

#include <stdbool.h>
#include <stdint.h>

struct block_log_port;

/* Accumulated outcome of one sweep. All counts are over the heights that
 * were actually iterated (blocks_checked). On the first failure of any
 * class, first_fail_height records the height and first_fail_reason a short
 * static reason string; both are also set when the sweep stops early. */
struct replay_verify_report {
    uint64_t    blocks_checked;     /* blocks read + verified                */
    uint64_t    pow_failures;       /* equihash or difficulty-target misses  */
    uint64_t    linkage_failures;   /* non-contiguous hashPrevBlock          */
    uint64_t    merkle_failures;    /* header merkle root != tx merkle root  */
    int64_t     first_fail_height;  /* -1 if no failure observed             */
    const char *first_fail_reason;  /* static string; NULL if no failure     */
    uint32_t    start_height;       /* echo of the requested start           */
    uint32_t    end_height;         /* last height the sweep intended to read*/
    uint32_t    tip_height;         /* legacy log tip at open time           */
};

/* Run the sweep against the legacy block log under `datadir`.
 *
 * start_height : first height to verify (inclusive).
 * max_blocks   : maximum number of blocks to read; 0 means "to tip".
 * out          : caller-owned report, fully populated on ZCL_OK and
 *                partially populated (best effort) on failure.
 *
 * Returns ZCL_OK when the sweep ran to completion (which is independent of
 * whether any block failed verification — inspect the report counts for
 * that). Returns a non-OK result only on operational failure (NULL args,
 * datadir unreadable, log open failed, a block that could not be
 * deserialized). The block_log adapter is NOT thread-safe; call from a
 * single thread.
 */
struct zcl_result replay_verify_run(const char *datadir,
                                     uint32_t start_height,
                                     uint64_t max_blocks,
                                     struct replay_verify_report *out);

/* Same sweep as replay_verify_run, but driven over a caller-supplied
 * block_log_port instead of opening the legacy datadir adapter. This is
 * the reusable core: replay_verify_run() opens block_log_legacy and
 * delegates here. It lets CI prove the verifier's teeth over a small,
 * self-contained block_log_file fixture — no live datadir, no
 * reimplemented crypto (the per-block verdict is still the canonical
 * check_block).
 *
 * `port` must have iter_from and tip_height populated. Returns ZCL_OK
 * when the sweep ran to completion (inspect the report counts for any
 * per-block verification failures), and a non-OK result only on
 * operational failure (NULL/incomplete port, empty log, start beyond
 * tip, iteration error, or a block that could not be deserialized).
 * The port is NOT closed here — the caller owns its lifecycle. */
struct zcl_result replay_verify_run_port(struct block_log_port *port,
                                         uint32_t start_height,
                                         uint64_t max_blocks,
                                         struct replay_verify_report *out);

#endif /* ZCL_SERVICES_REPLAY_VERIFY_SERVICE_H */
