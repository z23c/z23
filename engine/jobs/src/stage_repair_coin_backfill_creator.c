// repair-rung-ok:test_stage_repair_coin_backfill
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_repair_coin_backfill_creator — creator-proof helpers for the guarded
 * coin backfill.
 *
 * This TU owns the read-only G5/G7/G8 proof work: enumerate unresolved
 * prevouts exactly like script_validate resolves them, then bind each missing
 * outpoint to a hash-verified active-chain creator transaction. The caller
 * still owns refusal policy, no-spend scanning, and the single coins_kv write
 * transaction.
 */

#include "stage_repair_coin_backfill_internal.h"
#include "stage_repair_coin_backfill_util.h"

#include "coins/coins.h"
#include "core/amount.h"
#include "jobs/created_outputs_index.h"
#include "models/tx_index.h"
#include "storage/coins_kv.h"
#include "validation/main_constants.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

/* G5 enumeration — mirrors the validator's exact resolution order/semantics
 * (script_validate_created_index_prevout, script_validate_stage_prevout.c):
 * intra-block earlier tx, then created_outputs over [frontier..H], then
 * coins_kv usable iff height < frontier && height <= H. A coins row whose
 * HEIGHT is unusable is a metadata tear, not a missing coin -> refuse (do not
 * mint); a row whose specific vout is not live mirrors the validator's miss ->
 * candidate. Refusal is signalled via reason[0] != 0; returns false only on
 * infra error. Caller holds the progress lock. */
bool coin_backfill_enumerate_unresolved_prevouts(
    sqlite3 *db, const struct block *blk, int hole_height, int frontier,
    struct coin_backfill_outpoint *set, int *out_n, char reason[64])
{
    unsigned char script[MAX_SCRIPT_SIZE];
    *out_n = 0;
    reason[0] = '\0';

    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        if (transaction_is_coinbase(tx))
            continue;
        for (size_t vi = 0; vi < tx->num_vin; vi++) {
            const struct outpoint *op = &tx->vin[vi].prevout;

            bool resolved = false;
            for (size_t j = 0; j < i && !resolved; j++)
                if (uint256_cmp(&blk->vtx[j].hash, &op->hash) == 0)
                    resolved = true;
            if (resolved)
                continue;

            int64_t value = 0;
            size_t slen = 0;
            int created_h = -1;
            if (created_outputs_index_get_bounded(
                    db, op->hash.data, op->n, frontier, hole_height, &value,
                    script, sizeof(script), &slen, &created_h))
                continue;

            struct coins c;
            coins_init(&c);
            if (coins_kv_get_coins(db, op->hash.data, &c)) {
                bool height_ok = c.height < frontier &&
                                 c.height <= hole_height;
                bool usable = height_ok && op->n < c.num_vout &&
                              !tx_out_is_null(&c.vout[op->n]);
                int ch = c.height;
                coins_free(&c);
                if (usable)
                    continue;
                if (!height_ok) {
                    snprintf(reason, 64, "coin_present_unusable h=%d", ch);
                    return true;
                }
                /* height fine, this vout not live: validator-miss -> U */
            } else {
                coins_free(&c);
            }

            bool dup = false;
            for (int k = 0; k < *out_n && !dup; k++)
                if (memcmp(set[k].txid, op->hash.data, 32) == 0 &&
                    set[k].vout == op->n)
                    dup = true;
            if (dup)
                continue;
            if (*out_n >= COIN_BACKFILL_MAX_OUTPOINTS) {
                snprintf(reason, 64, "too_many_unresolved");
                return true;
            }
            memset(&set[*out_n], 0, sizeof(set[0]));
            memcpy(set[*out_n].txid, op->hash.data, 32);
            set[*out_n].vout = op->n;
            set[*out_n].creator_height = -1;
            (*out_n)++;
        }
    }
    return true;
}

static bool creator_fill_from_tx(struct coin_backfill_outpoint *op,
                                 const struct transaction *tx, int creator_h,
                                 int hole_height, char reason[64],
                                 enum coin_backfill_terminal_class *out_tc)
{
    if (op->vout >= tx->num_vout) {
        *out_tc = COIN_BACKFILL_TC_TERMINAL;
        snprintf(reason, 64, "vout_out_of_range %u h=%d", op->vout,
                 creator_h);
        return false;
    }
    int64_t value = tx->vout[op->vout].value;
    size_t slen = tx->vout[op->vout].script_pub_key.size;
    if (value < 0 || value > MAX_MONEY) {
        *out_tc = COIN_BACKFILL_TC_TERMINAL;
        snprintf(reason, 64, "value_out_of_range h=%d", creator_h);
        return false;
    }
    if (slen > MAX_SCRIPT_SIZE) {
        *out_tc = COIN_BACKFILL_TC_TERMINAL;
        snprintf(reason, 64, "script_too_long h=%d", creator_h);
        return false;
    }
    bool cb = transaction_is_coinbase(tx);
    if (cb && hole_height - creator_h < COINBASE_MATURITY) {
        /* genuinely-invalid spend: leave the hole, refuse — terminal */
        *out_tc = COIN_BACKFILL_TC_TERMINAL;
        snprintf(reason, 64, "coinbase_immature depth=%d",
                 hole_height - creator_h);
        return false;
    }
    op->creator_height = creator_h;
    op->value = value;
    op->script_len = slen;
    if (slen)
        memcpy(op->script, tx->vout[op->vout].script_pub_key.data, slen);
    op->is_coinbase = cb;
    return true;
}

static bool creator_find_in_active_window(
    const struct coin_backfill_io *io, int hole_height, int frontier,
    int delta_horizon, struct coin_backfill_outpoint *op, bool *out_found,
    char reason[64], enum coin_backfill_terminal_class *out_tc)
{
    (void)delta_horizon; /* Observability only; not a creator-proof boundary. */
    *out_found = false;
    int top = frontier - 1;
    if (top >= hole_height)
        top = hole_height - 1;
    int floor = hole_height - COIN_BACKFILL_CREATOR_SCAN_MAX_BLOCKS;
    if (floor < 0)
        floor = 0;
    if (top < floor) {
        *out_tc = COIN_BACKFILL_TC_RETRYABLE;
        snprintf(reason, 64, "creator_scan_horizon_exhausted floor=%d cap=%d",
                 floor, COIN_BACKFILL_CREATOR_SCAN_MAX_BLOCKS);
        return false;
    }

    int first_gap = -1;
    for (int h = top; h >= floor; h--) {
        struct block blk;
        struct uint256 hash;
        block_init(&blk);
        bool read_ok = io->read_block(io->user, h, &blk, &hash);
        if (!read_ok) {
            block_free(&blk);
            if (first_gap < 0)
                first_gap = h;
            continue;
        }

        for (size_t i = 0; i < blk.num_vtx; i++) {
            const struct transaction *tx = &blk.vtx[i];
            if (memcmp(tx->hash.data, op->txid, 32) != 0)
                continue;
            *out_found = true;
            bool ok = creator_fill_from_tx(op, tx, h, hole_height, reason,
                                           out_tc);
            block_free(&blk);
            return ok;
        }
        block_free(&blk);
    }

    if (first_gap >= 0) {
        *out_tc = COIN_BACKFILL_TC_RETRYABLE;
        snprintf(reason, 64, "creator_scan_gap h=%d", first_gap);
        return false;
    }
    if (floor > 0) {
        *out_tc = COIN_BACKFILL_TC_RETRYABLE;
        snprintf(reason, 64, "creator_scan_horizon_exhausted floor=%d cap=%d",
                 floor, COIN_BACKFILL_CREATOR_SCAN_MAX_BLOCKS);
        return false;
    }
    return true;
}

static bool creator_resolve_via_active_fallback(
    const struct coin_backfill_io *io, int hole_height, int frontier,
    int delta_horizon, struct coin_backfill_outpoint *op,
    const char *terminal_reason,
    enum coin_backfill_terminal_class terminal_tc,
    char reason[64], enum coin_backfill_terminal_class *out_tc)
{
    bool found = false;
    if (!creator_find_in_active_window(io, hole_height, frontier,
                                       delta_horizon, op, &found, reason,
                                       out_tc))
        return false;
    if (found)
        return true;
    *out_tc = terminal_tc;
    snprintf(reason, 64, "%s", terminal_reason);
    return false;
}

/* G7 + G8 — per-u creator resolution. The txindex row is only a HINT: the
 * authority is the hash-verified active-chain block at row.block_height
 * containing a tx whose RECOMPUTED double-SHA256 equals the wanted txid
 * (recon found corrupt txindex heights; garbage fails here and refuses). If
 * the projection misses, scan the bounded recent active-chain window before
 * accepting txindex_miss as terminal; stale node.db rows are not chain
 * evidence. Whole-set refusal via reason[0] != 0. */
void coin_backfill_resolve_creator(
    const struct coin_backfill_io *io, int hole_height, int frontier,
    int delta_horizon, struct coin_backfill_outpoint *set, int n,
    int *out_floor, char reason[64],
    enum coin_backfill_terminal_class *out_tc)
{
    struct block cblk;
    struct uint256 chash;
    int loaded_h = -1;
    *out_floor = -1;
    reason[0] = '\0';
    /* Default to RETRYABLE: only a path that proves the coin cannot exist in
     * the chain we hold upgrades this. A blank reason (success) leaves it
     * RETRYABLE, which is correct (the caller does not persist on success). */
    *out_tc = COIN_BACKFILL_TC_RETRYABLE;
    block_init(&cblk);

    if (!io->ndb) {
        /* No node.db handle (unit fixture / txindex-less run): the creator
         * cannot be resolved THIS process, but a later boot with the handle
         * wired may resolve it — transient, NOT a terminal verdict. */
        snprintf(reason, 64, "node_db_unavailable");
        block_free(&cblk);
        return;
    }

    for (int k = 0; k < n; k++) {
        struct db_tx_index row;
        char hex[65];
        coin_backfill_txid_hex(set[k].txid, hex);
        if (!db_tx_find(io->ndb, set[k].txid, &row)) {
            char terminal_reason[64];
            snprintf(terminal_reason, sizeof(terminal_reason),
                     "txindex_miss tx=%.16s", hex);
            if (creator_resolve_via_active_fallback(
                    io, hole_height, frontier, delta_horizon, &set[k],
                    terminal_reason,
                    COIN_BACKFILL_TC_TERMINAL_IF_TXINDEX_COMPLETE,
                    reason, out_tc)) {
                if (*out_floor < 0 || set[k].creator_height < *out_floor)
                    *out_floor = set[k].creator_height;
                continue;
            }
            break;
        }
        int ch = row.block_height;
        if (ch <= 0 || ch >= frontier || ch > hole_height) {
            char terminal_reason[64];
            snprintf(terminal_reason, sizeof(terminal_reason),
                     "creator_height_invalid h=%d", ch);
            if (creator_resolve_via_active_fallback(
                    io, hole_height, frontier, delta_horizon, &set[k],
                    terminal_reason, COIN_BACKFILL_TC_TERMINAL,
                    reason, out_tc)) {
                if (*out_floor < 0 || set[k].creator_height < *out_floor)
                    *out_floor = set[k].creator_height;
                continue;
            }
            break;
        }
        if (ch != loaded_h) {
            block_free(&cblk);
            block_init(&cblk);
            if (!io->read_block(io->user, ch, &cblk, &chash)) {
                char terminal_reason[64];
                snprintf(terminal_reason, sizeof(terminal_reason),
                         "creator_block_unreadable h=%d", ch);
                if (creator_resolve_via_active_fallback(
                        io, hole_height, frontier, delta_horizon, &set[k],
                        terminal_reason, COIN_BACKFILL_TC_RETRYABLE,
                        reason, out_tc)) {
                    if (*out_floor < 0 || set[k].creator_height < *out_floor)
                        *out_floor = set[k].creator_height;
                    loaded_h = -1;
                    continue;
                }
                break;
            }
            loaded_h = ch;
        }
        const struct transaction *tx = NULL;
        for (size_t i = 0; i < cblk.num_vtx && !tx; i++)
            if (memcmp(cblk.vtx[i].hash.data, set[k].txid, 32) == 0)
                tx = &cblk.vtx[i];
        if (!tx) {
            char terminal_reason[64];
            snprintf(terminal_reason, sizeof(terminal_reason),
                     "creator_txid_mismatch h=%d", ch);
            if (creator_resolve_via_active_fallback(
                    io, hole_height, frontier, delta_horizon, &set[k],
                    terminal_reason, COIN_BACKFILL_TC_TERMINAL,
                    reason, out_tc)) {
                if (*out_floor < 0 || set[k].creator_height < *out_floor)
                    *out_floor = set[k].creator_height;
                loaded_h = -1;
                continue;
            }
            break;
        }
        if (!creator_fill_from_tx(&set[k], tx, ch, hole_height, reason,
                                  out_tc))
            break;
        if (*out_floor < 0 || ch < *out_floor)
            *out_floor = ch;
    }
    block_free(&cblk);
}
