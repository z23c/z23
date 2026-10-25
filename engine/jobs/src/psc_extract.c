/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * psc_extract — Parallel State Compiler phase (a): per-block transparent delta
 * extraction into an event stream. See jobs/psc_internal.h.
 *
 * WHY A DEDICATED PASS (not lookup-free compute_block_delta): the serial
 * builder utxo_apply_compute_block_delta REQUIRES a live UTXO lookup — with
 * lookup==NULL every EXTERNAL (cross-block) spend resolves `found==false` and
 * it rejects the whole block as "spend_unknown_utxo" (utxo_apply_delta.c:346),
 * and the create-collision probe (:491) needs the lookup too. PSC's whole point
 * is to run WITHOUT that live dependency: existence, duplicate-outpoint (BIP30),
 * and create-before-spend become ORDERING properties the join validates. So
 * extraction is its own pass that applies only the BLOCK-LOCAL exclusion
 * predicates compute_block_delta applies (kept in lockstep with it):
 *   - genesis-hash skip           (utxo_apply_delta.c:250-253)
 *   - tx_out_is_null              (:459)
 *   - script_is_unspendable       (:476)
 *   - per-output MoneyRange       (:478)
 * and defers everything cross-block to the join. The per-tx value-balance /
 * coinbase-protection / subsidy-ceiling checks (compute_block_delta's other
 * rejects) are the design's "per-tx-parallel residue after join" (§2) and are
 * out of the P0 fold core — they do not affect terminal SET membership on a
 * finalized (already-validated) range, which is the merge-bar quantity.
 */
#include "jobs/psc_internal.h"

#include "chain/chainparams.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PSC_MAX_MONEY_ZAT 2100000000000000LL

/* ── event stream ──────────────────────────────────────────────────────── */

void psc_events_init(struct psc_events *e)
{
    memset(e, 0, sizeof(*e));
}

void psc_events_free(struct psc_events *e)
{
    if (!e) return;
    free(e->ev);
    free(e->scripts);
    memset(e, 0, sizeof(*e));
}

static bool psc_events_reserve(struct psc_events *e, size_t want)
{
    if (want <= e->cap) return true;
    size_t ncap = e->cap ? e->cap * 2 : 256;
    while (ncap < want) {
        if (ncap > SIZE_MAX / 2) {
            LOG_WARN("psc", "[psc] event vector capacity overflow");
            return false;
        }
        ncap *= 2;
    }
    struct psc_event *nv = zcl_realloc(e->ev, ncap * sizeof(*nv), "psc_events");
    if (!nv) {
        LOG_WARN("psc", "[psc] OOM growing event vector to %zu", ncap);
        return false;
    }
    e->ev = nv;
    e->cap = ncap;
    return true;
}

/* Append `len` script bytes to the pool, returning their offset in *off.
 * A zero-length script gets offset 0 and writes nothing. */
static bool psc_scripts_put(struct psc_events *e, const uint8_t *script,
                            uint32_t len, uint32_t *off)
{
    if (len == 0) { *off = 0; return true; }
    if (e->scr_used + len > e->scr_cap) {
        size_t ncap = e->scr_cap ? e->scr_cap * 2 : (1u << 16);
        while (ncap < e->scr_used + len) ncap *= 2;
        uint8_t *np = zcl_realloc(e->scripts, ncap, "psc_scripts");
        if (!np) {
            LOG_WARN("psc", "[psc] OOM growing script pool to %zu", ncap);
            return false;
        }
        e->scripts = np;
        e->scr_cap = ncap;
    }
    *off = (uint32_t)e->scr_used;
    memcpy(e->scripts + e->scr_used, script, len);
    e->scr_used += len;
    return true;
}

bool psc_events_add_create(struct psc_events *e, const uint8_t txid[32],
                           uint32_t vout, int64_t value, int32_t height,
                           bool is_coinbase, const uint8_t *script,
                           uint32_t script_len, uint64_t seq)
{
    if (!psc_events_reserve(e, e->n + 1)) return false;
    uint32_t off = 0;
    if (!psc_scripts_put(e, script, script_len, &off)) return false;
    struct psc_event *ev = &e->ev[e->n++];
    memset(ev, 0, sizeof(*ev));
    memcpy(ev->txid, txid, 32);
    ev->vout = vout;
    ev->seq = seq;
    ev->value = value;
    ev->script_off = off;
    ev->script_len = script_len;
    ev->height = height;
    ev->kind = PSC_CREATE;
    ev->is_coinbase = is_coinbase ? 1 : 0;
    return true;
}

bool psc_events_add_spend(struct psc_events *e, const uint8_t txid[32],
                          uint32_t vout, int32_t height, uint64_t seq)
{
    if (!psc_events_reserve(e, e->n + 1)) return false;
    struct psc_event *ev = &e->ev[e->n++];
    memset(ev, 0, sizeof(*ev));
    memcpy(ev->txid, txid, 32);
    ev->vout = vout;
    ev->seq = seq;
    ev->height = height;
    ev->kind = PSC_SPEND;
    return true;
}

/* ── per-block extraction ──────────────────────────────────────────────── */

/* Outcome of extracting one transaction's events. The extraction helpers
 * below never log — every LOG_ call stays in psc_extract_block — so failure
 * travels back to it as one of these codes. */
enum psc_extract_tx_status {
    PSC_EXTRACT_TX_OK,
    PSC_EXTRACT_TX_VALUE_OVERFLOW,
    PSC_EXTRACT_TX_APPEND_FAIL
};

/* Emit this tx's output CREATEs, advancing *create_idx across the block.
 * On PSC_EXTRACT_TX_VALUE_OVERFLOW, *bad_vout is the offending vout. */
static enum psc_extract_tx_status
psc_extract_tx_creates(const struct transaction *tx, uint32_t height,
                       struct psc_events *out, uint32_t *create_idx,
                       size_t *bad_vout)
{
    /* CREATEs — this tx's outputs (phase 0). */
    for (size_t vo = 0; vo < tx->num_vout; vo++) {
        const struct tx_out *txo = &tx->vout[vo];
        if (tx_out_is_null(txo))
            continue;
        if (script_is_unspendable(&txo->script_pub_key))
            continue;
        if (txo->value < 0 || txo->value > PSC_MAX_MONEY_ZAT) {
            *bad_vout = vo;
            return PSC_EXTRACT_TX_VALUE_OVERFLOW;
        }
        if (!psc_events_add_create(
                out, tx->hash.data, (uint32_t)vo, txo->value,
                (int32_t)height, transaction_is_coinbase(tx),
                txo->script_pub_key.data,
                (uint32_t)txo->script_pub_key.size,
                psc_seq_make(height, 0, *create_idx))) {
            return PSC_EXTRACT_TX_APPEND_FAIL;
        }
        (*create_idx)++;
    }
    return PSC_EXTRACT_TX_OK;
}

/* Emit this tx's input SPENDs, advancing *spend_idx across the block; the
 * coinbase exception is applied by the caller, psc_extract_tx_events. */
static bool psc_extract_tx_spends(const struct transaction *tx,
                                  uint32_t height, struct psc_events *out,
                                  uint32_t *spend_idx)
{
    for (size_t vi = 0; vi < tx->num_vin; vi++) {
        const struct outpoint *op = &tx->vin[vi].prevout;
        if (!psc_events_add_spend(out, op->hash.data, op->n,
                                  (int32_t)height,
                                  psc_seq_make(height, 1, *spend_idx))) {
            return false;
        }
        (*spend_idx)++;
    }
    return true;
}

/* Extract one transaction's events: CREATEs first, then SPENDs, with the
 * coinbase input exception between the two phases. */
static enum psc_extract_tx_status
psc_extract_tx_events(const struct transaction *tx, uint32_t height,
                      struct psc_events *out, uint32_t *create_idx,
                      uint32_t *spend_idx, size_t *bad_vout)
{
    enum psc_extract_tx_status st =
        psc_extract_tx_creates(tx, height, out, create_idx, bad_vout);
    if (st != PSC_EXTRACT_TX_OK)
        return st;

    /* SPENDs — this tx's inputs (phase 1), coinbase excepted. */
    if (transaction_is_coinbase(tx))
        return PSC_EXTRACT_TX_OK;
    if (!psc_extract_tx_spends(tx, height, out, spend_idx))
        return PSC_EXTRACT_TX_APPEND_FAIL;
    return PSC_EXTRACT_TX_OK;
}

bool psc_extract_block(const struct block *blk, uint32_t height,
                       struct psc_events *out, char reject[48])
{
    if (reject) reject[0] = '\0';
    if (!blk) {
        LOG_WARN("psc", "[psc] extract: NULL block at height=%u", height);
        if (reject) snprintf(reject, 48, "internal");
        return false;
    }

    /* THE genesis block contributes NOTHING (utxo_apply_delta.c:250-253): keyed
     * on the block HASH, not the height, exactly as zclassicd's genesis
     * early-exit. A synthetic non-genesis block at height 0 is folded normally. */
    struct uint256 this_hash;
    block_get_hash(blk, &this_hash);
    if (uint256_eq(&this_hash, &chain_params_get()->consensus.hashGenesisBlock))
        return true;

    uint32_t create_idx = 0, spend_idx = 0;
    for (size_t ti = 0; ti < blk->num_vtx; ti++) {
        const struct transaction *tx = &blk->vtx[ti];

        size_t bad_vout = 0;
        enum psc_extract_tx_status st =
            psc_extract_tx_events(tx, height, out, &create_idx, &spend_idx,
                                  &bad_vout);
        if (st == PSC_EXTRACT_TX_VALUE_OVERFLOW) {
            LOG_WARN("psc", "[psc] output value out of range height=%u "
                     "tx=%zu vout=%zu", height, ti, bad_vout);
            if (reject) snprintf(reject, 48, "value_overflow");
            return false;
        }
        if (st == PSC_EXTRACT_TX_APPEND_FAIL) {
            if (reject) snprintf(reject, 48, "internal");
            return false;
        }
    }
    return true;
}
