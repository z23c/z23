/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_delta — implementation. See jobs/utxo_apply_delta.h.
 *
 * Durable disconnect support for the utxo_apply Job: this file records
 * per-block inverse deltas and replays them when a stage-side reorg rewinds
 * abandoned branch rows. */

#include "platform/time_compat.h"
#include "jobs/utxo_apply_delta.h"
#include "jobs/replay_count_only.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/subsidy.h"
#include "core/uint256.h"
#include "event/event.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"  /* script_is_unspendable — UTXO-set exclusion */
#include "util/log_macros.h"
#include "util/reducer_stage_profile.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/checkpoint.h"
#include "validation/main_constants.h"
#include "validation/main_state.h"

#include <limits.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── Coinbase-maturity parity enforcement (DEFAULT-OFF) ────────────────
 * zclassicd's Consensus::CheckTxInputs (zclassic-cpp/src/main.cpp:2056-2060)
 * rejects "bad-txns-premature-spend-of-coinbase" when a tx spends a coinbase
 * output whose creation height is within COINBASE_MATURITY (100) of the
 * spending block's height (nSpendHeight - coins->nHeight < COINBASE_MATURITY,
 * where nSpendHeight = pindexPrev->nHeight + 1 = the height of the block being
 * connected). zclassic23 enforces this in the boot-reindex connect_block.c
 * path and the repair ladder, but the LIVE reducer fold below historically did
 * NOT. This flag adds the missing reject on the live path.
 *
 * Default false ⇒ the reducer fold makes the same accept/reject decision it
 * makes now: it does NOT reject a premature coinbase spend until the operator
 * opts in. This is a
 * tightening (reject) predicate, so it MUST stay default-off until a
 * FULL-HISTORY REPLAY against the real chain confirms ZERO false-rejects
 * first. That is the h=478544 lesson (CLAUDE.md "Consensus rule: validate
 * against the CHAIN, not the reference text"): a bounded predicate that looks
 * tighter-is-better can false-reject a real, already-mined block and halt
 * forward sync. zclassicd already rejected any premature coinbase spend, so
 * the real chain should contain none — but that must be PROVEN by replay
 * before flipping the default or passing the flag on the live node.
 *
 * Set by the node from the -enforce-coinbase-maturity argv flag (engine/entry/main.c).
 * _Atomic so background reducer/validation threads read it without a lock. */
_Atomic _Bool g_enforce_coinbase_maturity = false;

/* ── Delta-array lifetime ──────────────────────────────────────────── */

void free_delta_arr(struct delta_entry *arr, size_t n)
{
    if (arr) {
        for (size_t i = 0; i < n; i++)
            free(arr[i].script_owned);
    }
    free(arr);
}

void free_delta(struct delta_summary *s)
{
    free_delta_arr(s->spent, s->spent_count);
    free_delta_arr(s->added, s->added_count);
    s->spent = NULL;
    s->added = NULL;
}

/* ── Block-delta construction ──────────────────────────────────────── */

#define MAX_MONEY_ZAT 2100000000000000LL

static void failure_detail_set(uint8_t out[36], const struct uint256 *txid,
                               uint32_t vout)
{
    memset(out, 0, 36);
    if (txid) memcpy(out, txid->data, 32);
    out[32] = (uint8_t)(vout & 0xff);
    out[33] = (uint8_t)((vout >> 8) & 0xff);
    out[34] = (uint8_t)((vout >> 16) & 0xff);
    out[35] = (uint8_t)((vout >> 24) & 0xff);
}

struct added_index {
    size_t *slots;  /* delta_entry index + 1; 0 means empty */
    size_t mask;
};

static uint64_t added_index_hash(const struct uint256 *txid, uint32_t vout)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < sizeof(txid->data); i++) {
        h ^= txid->data[i];
        h *= 1099511628211ULL;
    }
    for (unsigned shift = 0; shift < 32; shift += 8) {
        h ^= (uint8_t)(vout >> shift);
        h *= 1099511628211ULL;
    }
    return h;
}

static bool added_index_init(struct added_index *idx, size_t add_cap)
{
    memset(idx, 0, sizeof(*idx));
    if (add_cap == 0)
        return true;
    if (add_cap > SIZE_MAX / 2)
        return false;
    size_t want = add_cap * 2;
    if (want < 8)
        want = 8;
    size_t cap = 1;
    while (cap < want) {
        if (cap > SIZE_MAX / 2)
            return false;
        cap <<= 1;
    }
    idx->slots = zcl_calloc(cap, sizeof(*idx->slots), "utxo_apply_add_index");
    if (!idx->slots)
        return false;
    idx->mask = cap - 1;
    return true;
}

static void added_index_free(struct added_index *idx)
{
    if (idx)
        free(idx->slots);
}

static bool added_index_lookup(const struct added_index *idx,
                               const struct delta_entry *added,
                               const struct uint256 *txid, uint32_t vout,
                               const struct delta_entry **out_entry)
{
    if (!idx->slots)
        return false;
    size_t pos = (size_t)added_index_hash(txid, vout) & idx->mask;
    for (size_t probes = 0; probes <= idx->mask; probes++) {
        size_t slot = idx->slots[pos];
        if (slot == 0)
            return false;
        const struct delta_entry *e = &added[slot - 1];
        if (e->vout == vout && uint256_eq(&e->txid, txid)) {
            if (out_entry)
                *out_entry = e;
            return true;
        }
        pos = (pos + 1) & idx->mask;
    }
    return false;
}

static bool added_index_insert(struct added_index *idx,
                               const struct delta_entry *added,
                               size_t entry_i)
{
    if (!idx->slots)
        return true;
    const struct delta_entry *entry = &added[entry_i];
    size_t pos = (size_t)added_index_hash(&entry->txid, entry->vout)
        & idx->mask;
    for (size_t probes = 0; probes <= idx->mask; probes++) {
        size_t slot = idx->slots[pos];
        if (slot == 0) {
            idx->slots[pos] = entry_i + 1;
            return true;
        }
        const struct delta_entry *e = &added[slot - 1];
        if (e->vout == entry->vout && uint256_eq(&e->txid, &entry->txid))
            return true;
        pos = (pos + 1) & idx->mask;
    }
    LOG_WARN("utxo_apply", "[utxo_apply] added-output lookup table full");
    return false;
}

static void delta_summary_init(struct delta_summary *s)
{
    memset(s, 0, sizeof(*s));
    s->ok = true;
    s->status = "verified";
}

static void delta_fail(struct delta_summary *s, const char *status,
                       const char *kind, const struct uint256 *txid,
                       uint32_t vout)
{
    s->ok = false;
    s->status = status;
    s->failure_kind = kind;
    failure_detail_set(s->failure_detail, txid, vout);
}

/* Loudly record a lookup failure (was the quietest error: no log). `kind`
 * ("lookup_spend"/"lookup_output") tags the log + failure_kind; detail kept. */
static void lookup_fail(struct delta_summary *s, const char *kind,
                        uint32_t height, const struct uint256 *txid,
                        uint32_t vout)
{
    char hex[65] = {0};
    if (txid) uint256_get_hex(txid, hex);
    LOG_WARN("utxo_apply", "[utxo_apply] %s failed height=%u txid=%s vout=%u",
             kind, height, hex, vout);
    s->ok = false; s->status = "internal_error"; s->failure_kind = kind;
}

void utxo_apply_compute_block_delta(const struct block *blk,
                                    uint32_t block_height,
                                    utxo_apply_lookup_fn lookup,
                                    void *lookup_user,
                                    struct delta_summary *out)
{
    delta_summary_init(out);
    if (!blk) {
        out->ok = false;
        out->status = "internal_error";
        out->failure_kind = "missing_block";
        return;
    }

    /* THE genesis block contributes NOTHING to the UTXO set. zclassicd
     * ConnectBlock (zclassic-cpp/src/main.cpp:2515-2527) special-cases the
     * genesis block — "skipping connection of its transactions (its coinbase is
     * unspendable)" — it SetBestBlock + returns BEFORE the per-tx UpdateCoins
     * loop (main.cpp:2657), so the genesis coinbase output NEVER enters
     * pcoinsTip. Mirror that EXACTLY: zclassicd keys the exclusion on the BLOCK
     * HASH (block.GetHash() == consensus.hashGenesisBlock), NOT on height. So
     * the fold adds 0 outputs and spends 0 inputs for THE genesis block only
     * (its computed hash equals the active params' genesis hash), keeping
     * coins_kv matching zclassicd (count + coins_kv_commitment) rather than
     * over-counting by +1 (the 1,354,770-vs-1,354,769 mint defect). An empty
     * ok=true delta: spent/added stay NULL, counts 0, total_value_delta 0
     * (delta_summary_init above). In production height 0 IS the real genesis so
     * the mint is unchanged; a synthetic non-genesis block at height 0 (its hash
     * != the params genesis hash) is folded normally, never wrongly dropped. */
    struct uint256 this_hash;
    block_get_hash(blk, &this_hash);
    if (uint256_eq(&this_hash, &chain_params_get()->consensus.hashGenesisBlock))
        return;

    size_t spend_cap = 0, add_cap = 0;
    for (size_t ti = 0; ti < blk->num_vtx; ti++) {
        const struct transaction *tx = &blk->vtx[ti];
        if (!transaction_is_coinbase(tx))
            spend_cap += tx->num_vin;
        add_cap += tx->num_vout;
    }

    struct delta_entry *spent = spend_cap
        ? zcl_calloc(spend_cap, sizeof(*spent), "utxo_apply_spent")
        : NULL;
    struct delta_entry *added = add_cap
        ? zcl_calloc(add_cap, sizeof(*added), "utxo_apply_added")
        : NULL;
    if ((spend_cap && !spent) || (add_cap && !added)) {
        out->ok = false;
        out->status = "internal_error";
        out->failure_kind = "alloc";
        free_delta_arr(spent, 0);
        free_delta_arr(added, 0);
        return;
    }
    /* Hand the arrays to `out` up front: every failure path below calls
     * free_delta(out), which frees the (possibly partly-filled) arrays
     * AND any owned restore-scripts up to the running counts. */
    out->spent = spent;
    out->added = added;

    struct added_index add_idx;
    if (!added_index_init(&add_idx, add_cap)) {
        out->ok = false;
        out->status = "internal_error";
        out->failure_kind = "alloc";
        free_delta(out);
        return;
    }
#define UTXO_DELTA_FAIL_AND_RETURN() do { \
        added_index_free(&add_idx); \
        free_delta(out); \
        return; \
    } while (0)

    /* Running fee total for the end-of-block coinbase subsidy ceiling below
     * (zclassicd's nFees accumulator, main.cpp:2695). */
    int64_t fees_total = 0;

    for (size_t ti = 0; ti < blk->num_vtx; ti++) {
        const struct transaction *tx = &blk->vtx[ti];
        int64_t tx_input_value = 0;
        bool tx_spends_coinbase = false;

        if (!transaction_is_coinbase(tx)) {
            for (size_t vi = 0; vi < tx->num_vin; vi++) {
                const struct outpoint *op = &tx->vin[vi].prevout;
                int64_t value = 0;
                /* Full restore pre-image for the spent coin. */
                uint32_t restore_height = 0;
                bool restore_coinbase = false;
                const uint8_t *restore_script = NULL;
                uint32_t restore_script_len = 0;
                /* Declared at the per-input scope (not inside the !found block
                 * below) so its lifetime spans the script copy further down:
                 * restore_script may alias lk's embedded buffer, which is
                 * memcpy'd into se->script_owned after that block has closed. */
                struct utxo_apply_lookup lk;
                const struct delta_entry *intra = NULL;
                bool found = added_index_lookup(&add_idx, added, &op->hash,
                                                op->n, &intra);
                if (found && intra) {
                    /* Created earlier in THIS block: its pre-image is the
                     * added entry we just recorded (height = this block). */
                    value = intra->value;
                    restore_height = block_height;
                    restore_coinbase = intra->is_coinbase;
                    restore_script = intra->script;
                    restore_script_len = intra->script_len;
                }
                if (!found) {
                    memset(&lk, 0, sizeof(lk));
                    if (lookup && !lookup(&op->hash, op->n, &lk, lookup_user)) {
                        lookup_fail(out, "lookup_spend", block_height,
                                    &op->hash, op->n);
                        UTXO_DELTA_FAIL_AND_RETURN();
                    }
                    found = lk.found;
                    value = lk.value;
                    restore_height = lk.height;
                    restore_coinbase = lk.is_coinbase;
                    restore_script = lk.script_len ? lk.script : NULL;
                    restore_script_len = lk.script_len;
                }
                if (!found) {
                    delta_fail(out, "spend_unknown_utxo",
                               "spend_unknown_utxo", &op->hash, op->n);
                    UTXO_DELTA_FAIL_AND_RETURN();
                }
                if (value < 0 || value > MAX_MONEY_ZAT) {
                    delta_fail(out, "value_overflow",
                               "input_value", &op->hash, op->n);
                    UTXO_DELTA_FAIL_AND_RETURN();
                }
                struct delta_entry *se = &spent[out->spent_count];
                se->txid = op->hash;
                se->vout = op->n;
                se->value = value;
                se->height = restore_height;
                se->is_coinbase = restore_coinbase;
                if (restore_coinbase)
                    tx_spends_coinbase = true;
                /* Coinbase maturity (DEFAULT-OFF, -enforce-coinbase-maturity).
                 * zclassicd CheckTxInputs (main.cpp:2056-2060) rejects a spend
                 * of a coinbase output younger than COINBASE_MATURITY (100):
                 * nSpendHeight - coins->nHeight < COINBASE_MATURITY. Here
                 * block_height is the spending block's height (== nSpendHeight)
                 * and restore_height is the spent coin's creation height
                 * (== coins->nHeight). Gated default-off: until enabled, the
                 * fold does NOT reject — same accept/reject decision as now.
                 * Enabling it
                 * requires a full-history replay confirming ZERO false-rejects
                 * first (see the g_enforce_coinbase_maturity contract above and
                 * the h=478544 doctrine). Guard against an underflow if a
                 * malformed pre-image ever reports a creation height above the
                 * spending height (treat as immature, never wrap to a huge
                 * unsigned depth). */
                if (atomic_load_explicit(&g_enforce_coinbase_maturity,
                                         memory_order_relaxed) &&
                    restore_coinbase &&
                    (block_height < restore_height ||
                     block_height - restore_height < COINBASE_MATURITY)) {
                    /* REPLAY GATE: in count-and-continue mode (env-gated
                     * ZCL_REPLAY_COUNT_ONLY), do NOT flip ok / halt the
                     * frontier. LOG + COUNT this fire and mark the block
                     * count_only_d2_skip so the stage authors NO coins for it
                     * and continues (strictly read/log/continue). The fold
                     * must reach genesis->tip to count ALL offenders, not just
                     * the first — but the offending block's coins are NEVER
                     * authored. When the env is unset replay_count_only_active()
                     * is false and this branch is never entered, so the
                     * normal delta_fail reject below runs as it does today. */
                    if (replay_count_only_active()) {
                        replay_count_only_note_d2_fire(block_height, &op->hash,
                                                       op->n);
                        out->count_only_d2_skip = true;
                        /* Read/log/continue: discard the partially-built delta
                         * (the block is not authored) and return ok=true so the
                         * stage skips authoring without taking the reject/halt
                         * path. */
                        added_index_free(&add_idx);
                        free_delta(out);
                        out->ok = true;
                        out->status = "verified";
                        out->failure_kind = NULL;
                        out->spent = NULL;
                        out->added = NULL;
                        out->spent_count = 0;
                        out->added_count = 0;
                        out->total_value_delta = 0;
                        return;
                    }
                    delta_fail(out, "coinbase_immature",
                               "bad-txns-premature-spend-of-coinbase",
                               &op->hash, op->n);
                    UTXO_DELTA_FAIL_AND_RETURN();
                }
                /* Own a copy of the restore script: the lookup buffer is
                 * stack-scoped and the intra-block add aliases the live
                 * block, both gone by disconnect time. */
                if (restore_script && restore_script_len) {
                    /* A UTXO scriptPubKey is consensus-bounded to
                     * MAX_SCRIPT_SIZE (== UTXO_APPLY_SCRIPT_MAX), the exact
                     * size of the stack lookup buffer restore_script points
                     * into. Reject rather than over-read that fixed buffer
                     * (or persist a truncated script that would corrupt the
                     * restored coin) if a lookup provider ever violates the
                     * contract. Unreachable with valid chain data. */
                    if (restore_script_len > UTXO_APPLY_SCRIPT_MAX) {
                        out->ok = false;
                        out->status = "internal_error";
                        out->failure_kind = "script_too_large";
                        UTXO_DELTA_FAIL_AND_RETURN();
                    }
                    se->script_owned =
                        zcl_malloc(restore_script_len, "utxo_apply_restore_sc");
                    if (!se->script_owned) {
                        out->ok = false;
                        out->status = "internal_error";
                        out->failure_kind = "alloc";
                        UTXO_DELTA_FAIL_AND_RETURN();
                    }
                    memcpy(se->script_owned, restore_script, restore_script_len);
                    se->script = se->script_owned;
                    se->script_len = restore_script_len;
                } else {
                    se->script = NULL;
                    se->script_len = 0;
                }
                out->spent_count++;
                out->total_value_delta -= value;
                tx_input_value += value;
            }
        }

        for (size_t vo = 0; vo < tx->num_vout; vo++) {
            const struct tx_out *txo = &tx->vout[vo];
            if (tx_out_is_null(txo))
                continue;
            /* Provably-unspendable outputs (OP_RETURN, or a scriptPubKey over
             * MAX_SCRIPT_SIZE) NEVER enter the UTXO set in zclassicd — Bitcoin
             * Core's AddCoin() skips IsUnspendable() (the SAME predicate
             * coins.c:86 applies on the seed path). Skip them here too, on the
             * LIVE fold, so coins_kv (count + coins_kv_commitment) matches
             * zclassicd exactly. Their value is still created-then-burned, but
             * that is accounted for OUTSIDE total_value_delta: the no-inflation
             * value-balance check below (line ~342) and the coinbase subsidy
             * ceiling use transaction_get_value_out(), which sums EVERY output
             * including OP_RETURN (transaction.c:186) — so excluding the burned
             * value from the UTXO-set delta does NOT relax value-balance.
             * total_value_delta is the UTXO-SET delta (no SELECT reader; it is
             * an audit column + a MoneyRange sanity bound only — grep confirms),
             * so the burned value MUST be excluded from it to stay consistent
             * with added_count and the coins it represents. */
            if (script_is_unspendable(&txo->script_pub_key))
                continue;
            if (txo->value < 0 || txo->value > MAX_MONEY_ZAT) {
                delta_fail(out, "value_overflow", "output_value",
                           &tx->hash, (uint32_t)vo);
                UTXO_DELTA_FAIL_AND_RETURN();
            }
            if (added_index_lookup(&add_idx, added, &tx->hash, (uint32_t)vo,
                                   NULL)) {
                delta_fail(out, "utxo_collision", "duplicate_output",
                           &tx->hash, (uint32_t)vo);
                UTXO_DELTA_FAIL_AND_RETURN();
            }
            struct utxo_apply_lookup lk;
            memset(&lk, 0, sizeof(lk));
            if (lookup && !lookup(&tx->hash, (uint32_t)vo, &lk, lookup_user)) {
                lookup_fail(out, "lookup_output", block_height,
                            &tx->hash, (uint32_t)vo);
                UTXO_DELTA_FAIL_AND_RETURN();
            }
            if (lk.found) {
                delta_fail(out, "utxo_collision", "utxo_collision",
                           &tx->hash, (uint32_t)vo);
                UTXO_DELTA_FAIL_AND_RETURN();
            }
            size_t add_i = out->added_count;
            added[add_i].txid = tx->hash;
            added[add_i].vout = (uint32_t)vo;
            added[add_i].value = txo->value;
            added[add_i].script = txo->script_pub_key.data;
            added[add_i].script_len =
                (uint32_t)txo->script_pub_key.size;
            added[add_i].is_coinbase = transaction_is_coinbase(tx);
            if (!added_index_insert(&add_idx, added, add_i)) {
                LOG_WARN("utxo_apply",
                         "[utxo_apply] added-output index insert failed "
                         "height=%u entry=%zu", block_height, add_i);
                out->ok = false;
                out->status = "internal_error";
                out->failure_kind = "added_index";
                UTXO_DELTA_FAIL_AND_RETURN();
            }
            out->added_count++;
            out->total_value_delta += txo->value;
        }

        if (!transaction_is_coinbase(tx)) {
            /* Coinbase outputs may be spent ONLY to shielded outputs.
             * zclassicd's Consensus::CheckTxInputs (zclassic-cpp/src/main.cpp
             * :2062-2070) rejects bad-txns-coinbase-spend-has-transparent-outputs
             * when a tx spends a coinbase output and has any transparent output,
             * gated by fCoinbaseEnforcedProtectionEnabled (always true on a
             * normal node) AND the per-chain fCoinbaseMustBeProtected (true on
             * mainnet/testnet, false on regtest). connect_block.c is dead
             * (boot-reindex only), so the reducer is the live connect path and
             * the rule must fire here. History-safe: zclassicd already rejected
             * any such tx, so no block on the immutable chain violates it. */
            if (tx_spends_coinbase && tx->num_vout != 0 &&
                chain_params_get()->consensus.fCoinbaseMustBeProtected) {
                delta_fail(out, "coinbase_protect",
                           "bad-txns-coinbase-spend-has-transparent-outputs",
                           &tx->hash, 0);
                UTXO_DELTA_FAIL_AND_RETURN();
            }
            /* Full Zcash money rule. The canonical check (connect_block.c
             * value_in<value_out -> "bad-txns-in-belowout") has NO production
             * caller, so this is the ONLY no-inflation guard on the reducer
             * path a connected block takes — it must be correct, not dropped.
             *   value_in  = transparent_in + max(0, value_balance) + Σ vpub_new
             *   value_out = transparent_out + max(0,-value_balance) + Σ vpub_old
             * The prior transparent-only test (tx_output_value > tx_input_value)
             * false-rejected a legitimate shielded->transparent unshield, where
             * value_balance>0 funds transparent outputs so transparent_out can
             * exceed transparent_in (the height-3,138,977 wedge). The two helpers
             * already MoneyRange-guard every partial sum and return -1 on
             * overflow. */
            int64_t sh_in = transaction_get_shielded_value_in(tx);
            int64_t value_out_full = transaction_get_value_out(tx);
            if (sh_in < 0 || value_out_full < 0 ||
                sh_in > MAX_MONEY_ZAT - tx_input_value) {
                delta_fail(out, "value_overflow", "inputvalues_outofrange",
                           &tx->hash, 0);
                UTXO_DELTA_FAIL_AND_RETURN();
            }
            int64_t value_in_full = tx_input_value + sh_in;
            if (value_in_full < value_out_full) {
                delta_fail(out, "value_overflow", "outputs_exceed_inputs",
                           &tx->hash, 0);
                UTXO_DELTA_FAIL_AND_RETURN();
            }
            /* Accumulate this tx's fee for the coinbase ceiling. tx_fee >= 0
             * by the check above, and value_in_full is already
             * MoneyRange-capped, so only the RUNNING TOTAL can leave range —
             * the exact guard connect_block.c:479 applies
             * (bad-txns-fee-outofrange). */
            int64_t tx_fee = value_in_full - value_out_full;
            if (tx_fee > MAX_MONEY_ZAT - fees_total) {
                delta_fail(out, "value_overflow", "fee_outofrange",
                           &tx->hash, 0);
                UTXO_DELTA_FAIL_AND_RETURN();
            }
            fees_total += tx_fee;
        }
    }

    /* Coinbase subsidy ceiling — the inflation cap. zclassicd ConnectBlock
     * (main.cpp:2695-2700): blockReward = nFees + GetBlockSubsidy(height);
     * a coinbase minting MORE than that is "bad-cb-amount". The canonical C
     * port (connect_block.c:655-668) is dead (boot-reindex only), so the
     * reducer path a connected block takes must enforce it here — without it
     * a miner could mint arbitrary coins. THE genesis block already returned
     * above (the hash-keyed early-exit), exactly as zclassicd's genesis
     * early-exit (main.cpp:2515-2527) returns before any tx/reward checks; the
     * block_height > 0 guard kept here is belt-and-suspenders for a height-0
     * coinbase (the subsidy ramp yields a 0 ceiling at height 0, which the
     * genesis coinbase is exempt from). Status is "bad_cb_amount", deliberately
     * NOT "value_overflow": the repair machinery keys on "value_overflow" as
     * a repairable-hole class (utxo_apply_delta_repair.c,
     * stage_repair_reducer_frontier_coin.c) and must never treat inflation
     * as repairable. */
    if (block_height > 0 && blk->num_vtx > 0 &&
        transaction_is_coinbase(&blk->vtx[0])) {
        int64_t subsidy = get_block_subsidy((int)block_height,
                                            &chain_params_get()->consensus);
        if (fees_total > INT64_MAX - subsidy) {
            delta_fail(out, "bad_cb_amount", "bad-cb-reward-overflow",
                       &blk->vtx[0].hash, 0);
            UTXO_DELTA_FAIL_AND_RETURN();
        }
        /* transaction_get_value_out returns -1 on a MoneyRange violation;
         * comparing -1 against the reward would FALSE-PASS, so a negative
         * sentinel must reject explicitly. */
        int64_t cb_out = transaction_get_value_out(&blk->vtx[0]);
        if (cb_out < 0 || cb_out > fees_total + subsidy) {
            delta_fail(out, "bad_cb_amount", "bad-cb-amount",
                       &blk->vtx[0].hash, 0);
            UTXO_DELTA_FAIL_AND_RETURN();
        }
    }

    if (out->total_value_delta > MAX_MONEY_ZAT ||
        out->total_value_delta < -MAX_MONEY_ZAT) {
        out->ok = false;
        out->status = "value_overflow";
        out->failure_kind = "total_value_delta";
        UTXO_DELTA_FAIL_AND_RETURN();
    }

    /* Success: out->spent/out->added own the arrays (see header). */
    added_index_free(&add_idx);
#undef UTXO_DELTA_FAIL_AND_RETURN
}

/* ── Schema ────────────────────────────────────────────────────────── */

/* Per-block inverse-delta record. One row per applied height carries the OLD branch
 * hash (so a same-height fork is distinguishable) plus the spent[] and
 * added[] blobs needed to emit inverse EV_UTXO_* events on a disconnect:
 *   spent_blob: per restored coin  txid|vout|value|height|is_coinbase|
 *                                  script_len|script  (everything ADD needs)
 *   added_blob: per erased coin    txid|vout            (everything SPEND needs)
 * NOTE: currently append-only — NOT yet pruned. A finality-floor prune is gated
 * on retiring the reducer-frontier repair ladder, whose inverse-delta walkers
 * have no finality clamp (see docs/work/canonical-frontier-derived-state-plan.md).
 * Until then this table grows O(chain); the only DELETE is the reorg range. */
bool utxo_apply_ensure_delta_schema(sqlite3 *db)
{
    static const char *const sql =
        "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
        "  height       INTEGER PRIMARY KEY,"
        "  branch_hash  BLOB    NOT NULL,"
        "  spent_blob   BLOB    NOT NULL,"
        "  added_blob   BLOB    NOT NULL"
        ")";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] delta schema ensure failed: %s", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

/* ── Inverse-delta (de)serialization ──────────────────────────────────
 * Little-endian, length-prefixed. Wire layout matches the load below; it
 * is internal to this process (progress.db is local) so no versioning. */

static void blob_put_u32(uint8_t **p, uint32_t v)
{
    (*p)[0] = (uint8_t)(v & 0xff);
    (*p)[1] = (uint8_t)((v >> 8) & 0xff);
    (*p)[2] = (uint8_t)((v >> 16) & 0xff);
    (*p)[3] = (uint8_t)((v >> 24) & 0xff);
    *p += 4;
}

static void blob_put_i64(uint8_t **p, int64_t v)
{
    uint64_t u = (uint64_t)v;
    for (int i = 0; i < 8; i++) (*p)[i] = (uint8_t)((u >> (8 * i)) & 0xff);
    *p += 8;
}

/* spent entry: 32(txid)+4(vout)+8(value)+4(height)+1(coinbase)+4(slen)+slen */
static size_t spent_entry_size(const struct delta_entry *e)
{
    return 32 + 4 + 8 + 4 + 1 + 4 + (size_t)e->script_len;
}

static uint8_t *serialize_spent(const struct delta_summary *s, size_t *out_len)
{
    size_t total = 0;
    for (size_t i = 0; i < s->spent_count; i++)
        total += spent_entry_size(&s->spent[i]);
    uint8_t *buf = zcl_malloc(total ? total : 1, "utxo_apply_spent_blob");
    if (!buf) { *out_len = 0; return NULL; }
    uint8_t *p = buf;
    for (size_t i = 0; i < s->spent_count; i++) {
        const struct delta_entry *e = &s->spent[i];
        memcpy(p, e->txid.data, 32); p += 32;
        blob_put_u32(&p, e->vout);
        blob_put_i64(&p, e->value);
        blob_put_u32(&p, e->height);
        *p++ = e->is_coinbase ? 1 : 0;
        blob_put_u32(&p, e->script_len);
        if (e->script_len) { memcpy(p, e->script, e->script_len); p += e->script_len; }
    }
    *out_len = total;
    return buf;
}

/* added entry: 32(txid)+4(vout) — SPEND needs only the outpoint. */
static uint8_t *serialize_added(const struct delta_summary *s, size_t *out_len)
{
    size_t total = s->added_count * (size_t)(32 + 4);
    uint8_t *buf = zcl_malloc(total ? total : 1, "utxo_apply_added_blob");
    if (!buf) { *out_len = 0; return NULL; }
    uint8_t *p = buf;
    for (size_t i = 0; i < s->added_count; i++) {
        memcpy(p, s->added[i].txid.data, 32); p += 32;
        blob_put_u32(&p, s->added[i].vout);
    }
    *out_len = total;
    return buf;
}

static bool delta_persist_impl(sqlite3 *db, int height,
                               const struct uint256 *branch_hash,
                               const struct delta_summary *s)
{
    size_t spent_len = 0, added_len = 0;
    uint8_t *spent_blob = serialize_spent(s, &spent_len);
    uint8_t *added_blob = serialize_added(s, &added_len);
    if (!spent_blob || !added_blob) {
        free(spent_blob); free(added_blob);
        LOG_WARN("utxo_apply", "[utxo_apply] delta serialize alloc failed h=%d", height);
        return false;
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO utxo_apply_delta "
        "(height, branch_hash, spent_blob, added_blob) VALUES (?,?,?,?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] delta prepare failed: %s", sqlite3_errmsg(db));
        free(spent_blob); free(added_blob);
        return false;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)height);
    sqlite3_bind_blob (stmt, 2, branch_hash ? branch_hash->data : NULL,
                       branch_hash ? 32 : 0, SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 3, spent_blob, (int)spent_len, SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 4, added_blob, (int)added_len, SQLITE_STATIC);
    rc = sqlite3_step(stmt);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(stmt);
    free(spent_blob); free(added_blob);
    if (rc != SQLITE_DONE) {
        LOG_WARN("utxo_apply", "[utxo_apply] delta insert h=%d rc=%d", height, rc);
        return false;
    }
    return true;
}

/* Fold-path attribution (RPF_UA_DELTA_PERSIST_US). */
bool utxo_apply_delta_persist(sqlite3 *db, int height,
                              const struct uint256 *branch_hash,
                              const struct delta_summary *s)
{
    const int64_t t0 = platform_time_monotonic_us();
    bool ok = delta_persist_impl(db, height, branch_hash, s);
    reducer_stage_profile_observe_us(
        REDUCER_PROFILE_UTXO_APPLY, RPF_UA_DELTA_PERSIST_US,
        (uint64_t)(platform_time_monotonic_us() - t0));
    return ok;
}
