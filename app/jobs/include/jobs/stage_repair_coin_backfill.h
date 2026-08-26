/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_repair_coin_backfill — guarded active-chain backfill for
 * prevout_unresolved frontier holes: a coin that is absent from coins_kv and
 * not available through created_outputs at the current replay boundary.
 * Re-derives the coin from the raw creating block, hash-verified on the active
 * chain, and inserts it ONLY after a chain-bound no-spend proof over every
 * applied active-chain block in (creator, frontier). The inverse-delta horizon
 * is observability, not an eligibility boundary: recent-window holes still
 * require active-chain proof and unprovable cases refuse loudly. The guard
 * ladder (G0-G10) is inlined in stage_repair_coin_backfill.c; the write
 * transaction it gates is the sole consensus mutation (coins_kv insert only —
 * never a cursor, a *_log row, or tip_finalize_log). */

#ifndef ZCL_JOBS_STAGE_REPAIR_COIN_BACKFILL_H
#define ZCL_JOBS_STAGE_REPAIR_COIN_BACKFILL_H

#include "core/uint256.h"
#include "primitives/block.h"
#include "script/script.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct sqlite3;
struct main_state;
struct node_db;
struct json_value;

enum coin_backfill_status {
    COIN_BACKFILL_NOT_APPLICABLE = 0, /* no unresolved old-coin prevouts: fall through */
    COIN_BACKFILL_SCANNING,           /* no-spend scan progressed; resume next tick */
    COIN_BACKFILL_REPAIRED,           /* coin(s) inserted; stale-script replay proceeds */
    COIN_BACKFILL_OWNER_REFUSED,      /* env ack missing — pages directly */
    COIN_BACKFILL_REFUSED_SPENT,      /* prevout provably spent <= frontier-1 */
    COIN_BACKFILL_REFUSED_UNPROVABLE, /* guard failed / scan gap / creator unresolvable */
    COIN_BACKFILL_MARKER_SEEN,        /* outpoint already backfilled once and lost AGAIN */
};

struct coin_backfill_outpoint {
    uint8_t  txid[32];          /* internal byte order */
    uint32_t vout;
    int32_t  creator_height;
    int64_t  value;
    uint8_t  script[MAX_SCRIPT_SIZE];
    size_t   script_len;
    bool     is_coinbase;
};
/* NOTE: 64 * sizeof(struct coin_backfill_outpoint) is ~644 KB. The U set is
 * heap-allocated ONCE via zcl_malloc per call and freed before return —
 * NEVER stack-allocated (the condition tick runs on the self_heal
 * supervisor thread). */
#define COIN_BACKFILL_MAX_OUTPOINTS 64

/* Test seam: production wires stage_repair_read_active_block_checked +
 * app_runtime_node_db(). */
struct coin_backfill_io {
    bool (*read_block)(void *user, int height, struct block *blk,
                       struct uint256 *hash);   /* active-chain, hash-verified */
    void *user;
    struct node_db *ndb;                        /* txid -> creating height (txindex) */
};

struct coin_backfill_result {
    enum coin_backfill_status status;
    int  hole_height;
    int  unresolved_count;     /* |U| */
    int  inserted_count;
    int  scan_next_height;     /* resumable cursor */
    int  scan_top_height;      /* frontier-1 */
    int  creator_floor;        /* min creator height across U */
    int  delta_horizon;        /* lowest contiguous utxo_apply_log height */
    char refuse_reason[64];
};

/* Entry point called from the replay-repair dispatcher. apply=false = detect
 * (enumeration + guards only, no scan, no writes). Returns false only on
 * infrastructure error (caller surfaces COND_REMEDY_FAILED).
 *
 * CONTRACT (normative): guards G1-G8 re-run on EVERY call, including every
 * apply tick of a multi-tick scan; the insert-tx active-chain re-reads are
 * load-bearing against persistent reorgs. Refusals are whole-set. Every
 * refusal status (OWNER_REFUSED, REFUSED_SPENT, REFUSED_UNPROVABLE,
 * MARKER_SEEN) emits a typed blocker AND EV_OPERATOR_NEEDED directly from
 * this Job (once-latched per (H,holehash,status)); paging never depends on
 * condition-engine attempt exhaustion. */
bool stage_repair_coin_backfill_try(struct sqlite3 *db, struct main_state *ms,
                                    const struct coin_backfill_io *io,
                                    bool apply, struct coin_backfill_result *out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
bool coin_backfill_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_JOBS_STAGE_REPAIR_COIN_BACKFILL_H */
