/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Canonical input reconstruction for an abandoned UTXO suffix. */

#include "utxo_apply_delta_internal.h"

#include "base/safe_alloc.h"
#include "jobs/created_outputs_index.h"
#include "jobs/stage_body_index.h"
#include "jobs/stage_helpers.h"
#include "primitives/block.h"
#include "storage/coins_kv.h"
#include "util/log_macros.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct suffix_seen_input {
    struct uint256 hash;
    uint32_t n;
};

static bool suffix_seen_add(struct suffix_seen_input **seen,
                            size_t *count, size_t *capacity,
                            const struct outpoint *op)
{
    for (size_t i = 0; i < *count; i++) {
        if ((*seen)[i].n == op->n &&
            uint256_eq(&(*seen)[i].hash, &op->hash)) {
            LOG_WARN("utxo_apply",
                     "[utxo_apply] future coin repair refused: duplicate "
                     "transparent input in canonical suffix");
            return false;
        }
    }
    if (*count == *capacity) {
        size_t next = *capacity == 0 ? 64 : *capacity * 2;
        if (next < *capacity || next > SIZE_MAX / sizeof(**seen)) {
            LOG_WARN("utxo_apply",
                     "[utxo_apply] future coin repair input set overflow");
            return false;
        }
        struct suffix_seen_input *grown = zcl_realloc(
            *seen, next * sizeof(**seen), "utxo suffix seen inputs");
        if (!grown) {
            LOG_WARN("utxo_apply",
                     "[utxo_apply] future coin repair input set OOM");
            return false;
        }
        *seen = grown;
        *capacity = next;
    }
    (*seen)[*count].hash = op->hash;
    (*seen)[*count].n = op->n;
    (*count)++;
    return true;
}

static bool creator_coin_from_canonical_body(
    sqlite3 *db, struct main_state *ms, const char *datadir,
    utxo_apply_reader_fn reader, void *reader_user,
    const struct outpoint *op, int creator_limit,
    int64_t *value, uint8_t script[UTXO_APPLY_SCRIPT_MAX],
    size_t *script_len, int *creator_height, bool *is_coinbase)
{
    if (!created_outputs_index_get_bounded(
            db, op->hash.data, op->n, 0, creator_limit - 1, value, script,
            UTXO_APPLY_SCRIPT_MAX, script_len, creator_height)) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] future coin repair refused: pre-suffix "
                 "creator output unavailable");
        return false;
    }
    struct block_index *bi = stage_body_index_at(ms, *creator_height);
    struct block creator;
    block_init(&creator);
    if (!bi || bi->nHeight != *creator_height || !bi->phashBlock ||
        !stage_read_block(&creator, bi, *creator_height, datadir,
                          reader, reader_user)) {
        block_free(&creator);
        LOG_WARN("utxo_apply",
                 "[utxo_apply] future coin repair refused: creator body "
                 "unavailable h=%d", *creator_height);
        return false;
    }

    bool matched = false;
    for (size_t ti = 0; ti < creator.num_vtx; ti++) {
        const struct transaction *tx = &creator.vtx[ti];
        if (!uint256_eq(&tx->hash, &op->hash))
            continue;
        if (op->n >= tx->num_vout)
            break;
        const struct tx_out *out = &tx->vout[op->n];
        matched = out->value == *value &&
                  out->script_pub_key.size == *script_len &&
                  (*script_len == 0 ||
                   memcmp(out->script_pub_key.data, script,
                          *script_len) == 0);
        if (matched)
            *is_coinbase = transaction_is_coinbase(tx);
        break;
    }
    block_free(&creator);
    if (!matched) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] future coin repair refused: creator proof "
                 "mismatch h=%d vout=%u", *creator_height, op->n);
        return false;
    }
    return true;
}

static bool live_coin_matches(sqlite3 *db, const struct outpoint *op,
                              int64_t value, const uint8_t *script,
                              size_t script_len, int creator_height,
                              bool is_coinbase)
{
    uint8_t live_script[UTXO_APPLY_SCRIPT_MAX];
    int64_t live_value = 0;
    int32_t live_height = -1;
    bool live_coinbase = false;
    size_t live_script_len = 0;
    if (!coins_kv_get_prevout(db, op->hash.data, op->n, &live_value,
                              live_script, sizeof(live_script),
                              &live_script_len, &live_height,
                              &live_coinbase)) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] future coin repair could not read live input");
        return false;
    }
    return live_value == value && live_height == creator_height &&
           live_coinbase == is_coinbase && live_script_len == script_len &&
           (script_len == 0 ||
            memcmp(live_script, script, script_len) == 0);
}

/* Replay the inverse of each transparent spend.  A creator below the applied
 * frontier is either restored or proved already live; a creator in the gap is
 * proved but left absent for the normal reducer to create. */
bool utxo_apply_restore_suffix_inputs(
    sqlite3 *db, struct main_state *ms, const char *datadir,
    utxo_apply_reader_fn reader, void *reader_user, int applied_first,
    int scan_first, int last, int64_t *restored_out,
    int64_t *already_live_out)
{
    struct suffix_seen_input *seen = NULL;
    size_t seen_count = 0;
    size_t seen_capacity = 0;
    bool ok = true;
    *restored_out = 0;
    *already_live_out = 0;
    for (int h = scan_first; h <= last && ok; h++) {
        struct block_index *bi = stage_body_index_at(ms, h);
        struct block blk;
        block_init(&blk);
        if (!bi || bi->nHeight != h || !bi->phashBlock ||
            !stage_read_block(&blk, bi, h, datadir, reader, reader_user)) {
            block_free(&blk);
            LOG_WARN("utxo_apply",
                     "[utxo_apply] future coin repair refused while "
                     "restoring spends: body unavailable h=%d", h);
            ok = false;
            break;
        }
        for (size_t ti = 0; ti < blk.num_vtx && ok; ti++) {
            const struct transaction *tx = &blk.vtx[ti];
            if (transaction_is_coinbase(tx))
                continue;
            for (size_t vi = 0; vi < tx->num_vin; vi++) {
                const struct outpoint *op = &tx->vin[vi].prevout;
                uint8_t script[UTXO_APPLY_SCRIPT_MAX];
                int64_t value = 0;
                size_t script_len = 0;
                int creator_height = -1;
                bool is_coinbase = false;
                if (!suffix_seen_add(&seen, &seen_count, &seen_capacity, op) ||
                    !creator_coin_from_canonical_body(
                        db, ms, datadir, reader, reader_user, op, scan_first,
                        &value, script, &script_len, &creator_height,
                        &is_coinbase)) {
                    LOG_WARN("utxo_apply",
                             "[utxo_apply] future coin repair refused: "
                             "could not prove h=%d tx=%zu vin=%zu "
                             "creator_h=%d", h, ti, vi, creator_height);
                    ok = false;
                    break;
                }
                bool live = coins_kv_exists(db, op->hash.data, op->n);
                if (creator_height < applied_first) {
                    if (live) {
                        if (!live_coin_matches(db, op, value, script,
                                               script_len, creator_height,
                                               is_coinbase)) {
                            LOG_WARN("utxo_apply",
                                     "[utxo_apply] future coin repair "
                                     "refused: live input mismatch h=%d "
                                     "tx=%zu vin=%zu", h, ti, vi);
                            ok = false;
                            break;
                        }
                        (*already_live_out)++;
                    } else if (!coins_kv_add(
                                   db, op->hash.data, op->n, value,
                                   creator_height, is_coinbase, script,
                                   script_len)) {
                        LOG_WARN("utxo_apply",
                                 "[utxo_apply] future coin repair refused: "
                                 "could not restore h=%d tx=%zu vin=%zu "
                                 "creator_h=%d", h, ti, vi, creator_height);
                        ok = false;
                        break;
                    } else {
                        (*restored_out)++;
                    }
                } else if (live) {
                    LOG_WARN("utxo_apply",
                             "[utxo_apply] future coin repair refused: "
                             "unapplied creator unexpectedly live h=%d "
                             "tx=%zu vin=%zu creator_h=%d", h, ti, vi,
                             creator_height);
                    ok = false;
                    break;
                }
            }
        }
        block_free(&blk);
    }
    free(seen);
    return ok;
}
