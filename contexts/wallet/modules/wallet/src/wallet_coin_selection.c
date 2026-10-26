/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Asset-safe wallet coin inventory and explicit-input transaction builder. */

#include "wallet/wallet.h"
#include "chain/chainparams.h"
#include "consensus/upgrades.h"
#include "core/utiltime.h"
#include "keys/key_io.h"
#include "script/standard.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "wallet/keystore.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static wallet_coin_reservation_probe g_reservation_probe;
static void *g_reservation_ctx;

struct selection_candidate {
    struct coin_entry coin;
    int64_t value;
    size_t original_index;
};

static int compare_candidates_desc(const void *lhs_raw, const void *rhs_raw)
{
    const struct selection_candidate *lhs = lhs_raw;
    const struct selection_candidate *rhs = rhs_raw;
    if (lhs->value != rhs->value)
        return lhs->value > rhs->value ? -1 : 1;
    int hash_order = uint256_cmp(&lhs->coin.wtx->tx.hash,
                                 &rhs->coin.wtx->tx.hash);
    if (hash_order != 0)
        return hash_order;
    if (lhs->coin.i != rhs->coin.i)
        return lhs->coin.i < rhs->coin.i ? -1 : 1;
    if (lhs->original_index == rhs->original_index)
        return 0;
    return lhs->original_index < rhs->original_index ? -1 : 1;
}

void wallet_set_coin_reservation_probe(wallet_coin_reservation_probe probe,
                                       void *ctx)
{
    /* Startup composition only: boot installs this before command/RPC worker
     * threads start selecting coins. The probe is pure and remains installed
     * for the process lifetime. */
    g_reservation_probe = probe;
    g_reservation_ctx = ctx;
}

static bool wallet_tx_has_listable_coins(const struct wallet_tx *wtx,
                                         bool only_confirmed)
{
    return wtx->used &&
           (!only_confirmed || wtx->confirms >= 1) &&
           (!transaction_is_coinbase(&wtx->tx) ||
            wallet_tx_get_blocks_to_maturity(wtx) <= 0);
}

static bool wallet_coin_output_available(const struct wallet *w,
                                         const struct wallet_tx *wtx,
                                         size_t j,
                                         bool include_zero_value,
                                         bool include_slp_reserved)
{
    const struct tx_out *out = &wtx->tx.vout[j];
    return (include_zero_value || out->value != 0) &&
           (include_slp_reserved || !g_reservation_probe ||
            !g_reservation_probe(&wtx->tx, (uint32_t)j,
                                 g_reservation_ctx)) &&
           wallet_is_mine(w, out) &&
           !wallet_is_outpoint_spent(w, &wtx->tx.hash, (uint32_t)j);
}

static bool wallet_coin_output_spendable(const struct wallet *w,
                                         const struct tx_out *out)
{
    bool can_spend = false;
    struct tx_destination coin_dest;
    if (script_extract_destination(&out->script_pub_key, &coin_dest) &&
        coin_dest.type == DEST_KEY_ID) {
        struct privkey test_key;
        can_spend = keystore_get_key(&w->keystore, &coin_dest.id.key,
                                     &test_key);
        if (can_spend)
            memory_cleanse(test_key.vch, 32);
    }
    return can_spend;
}

void wallet_available_coins_ex(const struct wallet *w,
                               struct coin_entry *coins_out,
                               size_t *num_coins, size_t max_coins,
                               bool only_confirmed, bool include_zero_value,
                               bool include_slp_reserved)
{
    *num_coins = 0;
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    for (size_t i = 0; i < MAX_WALLET_TX && *num_coins < max_coins; i++) {
        const struct wallet_tx *wtx = &w->map_wallet[i];
        if (!wallet_tx_has_listable_coins(wtx, only_confirmed))
            continue;
        for (size_t j = 0; j < wtx->tx.num_vout && *num_coins < max_coins; j++) {
            const struct tx_out *out = &wtx->tx.vout[j];
            if (!wallet_coin_output_available(w, wtx, j, include_zero_value,
                                              include_slp_reserved))
                continue;

            bool can_spend = wallet_coin_output_spendable(w, out);
            coins_out[*num_coins] = (struct coin_entry) {
                .wtx = wtx, .i = (unsigned int)j, .depth = wtx->confirms,
                .spendable = can_spend, .solvable = can_spend,
            };
            (*num_coins)++;
        }
    }
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
}

void wallet_available_coins(const struct wallet *w,
                             struct coin_entry *coins_out,
                             size_t *num_coins, size_t max_coins,
                             bool only_confirmed, bool include_zero_value)
{
    wallet_available_coins_ex(w, coins_out, num_coins, max_coins,
                              only_confirmed, include_zero_value, false);
}

int64_t wallet_default_fee(const struct wallet *w)
{
    if (!w)
        return 0;
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    int64_t fee = w->default_fee;
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
    return fee;
}

static bool wallet_coin_entry_usable(const struct coin_entry *entry)
{
    return entry->spendable && entry->wtx &&
           entry->i < entry->wtx->tx.num_vout;
}

static size_t wallet_find_smallest_sufficient(
    const struct coin_entry *available, size_t num_available,
    int64_t target_value, int64_t *best_value_out)
{
    size_t best_single = SIZE_MAX;
    int64_t best_single_value = INT64_MAX;
    for (size_t i = 0; i < num_available; i++) {
        if (!wallet_coin_entry_usable(&available[i]))
            continue;
        int64_t value = available[i].wtx->tx.vout[available[i].i].value;
        if (value < target_value || value > best_single_value)
            continue;
        if (value < best_single_value || best_single == SIZE_MAX ||
            uint256_cmp(&available[i].wtx->tx.hash,
                        &available[best_single].wtx->tx.hash) < 0 ||
            (uint256_eq(&available[i].wtx->tx.hash,
                        &available[best_single].wtx->tx.hash) &&
             available[i].i < available[best_single].i)) {
            best_single = i;
            best_single_value = value;
        }
    }
    *best_value_out = best_single_value;
    return best_single;
}

static bool wallet_select_coins_largest_first(
    const struct coin_entry *available, size_t num_available,
    int64_t target_value, struct coin_entry *selected, size_t *num_selected,
    size_t max_selected, int64_t *value_out)
{
    if (num_available > SIZE_MAX / sizeof(struct selection_candidate))
        return false;
    struct selection_candidate *candidates = zcl_malloc(
        num_available * sizeof(*candidates), "wallet_coin_candidates");
    if (!candidates)
        return false;
    size_t candidate_count = 0;
    for (size_t i = 0; i < num_available; i++) {
        if (!wallet_coin_entry_usable(&available[i]))
            continue;
        int64_t value = available[i].wtx->tx.vout[available[i].i].value;
        if (value <= 0)
            continue;
        candidates[candidate_count++] = (struct selection_candidate) {
            .coin = available[i], .value = value, .original_index = i,
        };
    }
    qsort(candidates, candidate_count, sizeof(*candidates),
          compare_candidates_desc);
    for (size_t i = 0;
         i < candidate_count && *num_selected < max_selected;
         i++) {
        if (*value_out > INT64_MAX - candidates[i].value) {
            free(candidates);
            *num_selected = 0;
            *value_out = 0;
            return false;
        }
        selected[(*num_selected)++] = candidates[i].coin;
        *value_out += candidates[i].value;
        if (*value_out >= target_value)
            break;
    }
    free(candidates);
    return *value_out >= target_value;
}

bool wallet_select_coins(const struct wallet *w,
                         const struct coin_entry *available,
                         size_t num_available, int64_t target_value,
                         struct coin_entry *selected, size_t *num_selected,
                         size_t max_selected, int64_t *value_out)
{
    (void)w;
    if (!num_selected || !value_out)
        return false;
    *num_selected = 0;
    *value_out = 0;
    if (target_value < 0 || (!available && num_available != 0) ||
        (!selected && max_selected != 0))
        return false;
    if (target_value == 0)
        return true;
    if (max_selected == 0)
        return false;

    /* A single input is always the lowest-input solution. Pick the smallest
     * sufficient coin so the resulting change is bounded and wallet insertion
     * order cannot change the transaction shape. */
    int64_t best_single_value = INT64_MAX;
    size_t best_single = wallet_find_smallest_sufficient(
        available, num_available, target_value, &best_single_value);
    if (best_single != SIZE_MAX) {
        selected[0] = available[best_single];
        *num_selected = 1;
        *value_out = best_single_value;
        return true;
    }

    /* No single coin covers the target. Largest-first minimizes the number of
     * inputs for the common fragmented-wallet case, which lowers signature
     * work and leaves more independent UTXOs available to concurrent reserved
     * intents. The stable outpoint tie-break makes selection reproducible. */
    return wallet_select_coins_largest_first(available, num_available,
                                             target_value, selected,
                                             num_selected, max_selected,
                                             value_out);
}

static bool wallet_liquidity_request_valid(
    const struct coin_entry *available, size_t num_available,
    int64_t agent_available_zat, int64_t recipient_value_zat,
    int64_t maximum_fee_zat, int64_t fanout_maximum_fee_zat,
    int requested_concurrency)
{
    return (available || num_available == 0) && agent_available_zat >= 0 &&
           recipient_value_zat > 0 && maximum_fee_zat >= 0 &&
           fanout_maximum_fee_zat >= 0 && requested_concurrency >= 1 &&
           requested_concurrency <= 50 &&
           recipient_value_zat <= INT64_MAX - maximum_fee_zat;
}

static bool wallet_liquidity_plan_fill_amounts(
    struct wallet_liquidity_plan *out)
{
    out->required_per_slot_zat = out->recipient_value_zat +
        out->maximum_fee_zat;
    if (out->required_per_slot_zat >
        INT64_MAX / out->requested_concurrency) {
        (void)snprintf(out->status, sizeof(out->status), "INVALID_REQUEST");
        (void)snprintf(out->reason, sizeof(out->reason),
                       "requested concurrency overflows the amount range");
        return false;
    }
    out->future_total_required_zat =
        out->required_per_slot_zat * out->requested_concurrency;
    out->fanout_output_value_zat = out->required_per_slot_zat;
    out->fanout_outputs_total_zat = out->future_total_required_zat;
    if (out->agent_available_zat > out->fanout_maximum_fee_zat)
        out->maximum_fanout_slots = (int)((out->agent_available_zat -
            out->fanout_maximum_fee_zat) / out->required_per_slot_zat);
    if (out->maximum_fanout_slots > 50)
        out->maximum_fanout_slots = 50;
    return true;
}

static bool wallet_liquidity_sum_transparent(const struct coin_entry *working,
                                             size_t num_available,
                                             int64_t *sum_out)
{
    for (size_t i = 0; i < num_available; i++) {
        if (!wallet_coin_entry_usable(&working[i]))
            continue;
        int64_t value = working[i].wtx->tx.vout[working[i].i].value;
        if (value <= 0)
            continue;
        if (*sum_out > INT64_MAX - value)
            return false;
        *sum_out += value;
    }
    return true;
}

static void wallet_liquidity_consume_picked(struct coin_entry *working,
                                            size_t num_available,
                                            const struct coin_entry *picked,
                                            size_t picked_count)
{
    for (size_t i = 0; i < picked_count; i++) {
        for (size_t j = 0; j < num_available; j++) {
            if (working[j].spendable &&
                working[j].wtx == picked[i].wtx &&
                working[j].i == picked[i].i) {
                working[j].spendable = false;
                break;
            }
        }
    }
}

static void wallet_liquidity_measure_slots(struct coin_entry *working,
                                           size_t num_available,
                                           struct coin_entry *picked,
                                           int requested_concurrency,
                                           struct wallet_liquidity_plan *out)
{
    while (out->current_independent_slots < requested_concurrency) {
        size_t picked_count = 0;
        int64_t picked_value = 0;
        if (!wallet_select_coins(NULL, working, num_available,
                                 out->required_per_slot_zat, picked,
                                 &picked_count, num_available,
                                 &picked_value))
            break;
        out->current_independent_slots++;
        out->current_inputs_used += (int)picked_count;
        wallet_liquidity_consume_picked(working, num_available, picked,
                                        picked_count);
    }
}

static void wallet_liquidity_plan_finish(struct wallet_liquidity_plan *out,
                                         int requested_concurrency)
{
    const bool policy_covers_future =
        out->future_total_required_zat <= out->agent_available_zat;
    const bool transparent_covers_fanout =
        out->fanout_outputs_total_zat <= out->transparent_available_zat &&
        out->fanout_maximum_fee_zat <= out->transparent_available_zat -
            out->fanout_outputs_total_zat;
    const bool policy_covers_fanout = policy_covers_future &&
        out->fanout_maximum_fee_zat <= out->agent_available_zat -
            out->future_total_required_zat;
    out->ready_now = policy_covers_future &&
        out->current_independent_slots >= requested_concurrency;
    out->fanout_possible = policy_covers_fanout && transparent_covers_fanout;
    out->fanout_recommended = !out->ready_now && out->fanout_possible;
    out->recommended_fanout_outputs = out->fanout_recommended
        ? requested_concurrency : 0;

    if (out->ready_now) {
        (void)snprintf(out->status, sizeof(out->status), "READY_NOW");
        (void)snprintf(out->reason, sizeof(out->reason),
                       "enough independent reserved-eligible UTXOs and policy allowance exist");
    } else if (!policy_covers_future) {
        (void)snprintf(out->status, sizeof(out->status),
                       "INSUFFICIENT_POLICY_BUDGET");
        (void)snprintf(out->reason, sizeof(out->reason),
                       "identity-bound agent allowance cannot cover every recipient plus maximum fee");
    } else if (!transparent_covers_fanout) {
        (void)snprintf(out->status, sizeof(out->status),
                       "NEEDS_TRANSPARENT_LIQUIDITY");
        (void)snprintf(out->reason, sizeof(out->reason),
                       "current transparent coins cannot fund the requested self-fanout plus its maximum fee");
    } else if (!policy_covers_fanout) {
        (void)snprintf(out->status, sizeof(out->status),
                       "FANOUT_FEE_EXCEEDS_BUDGET");
        (void)snprintf(out->reason, sizeof(out->reason),
                       "future payments fit the allowance but the preparation fee does not");
    } else {
        (void)snprintf(out->status, sizeof(out->status), "NEEDS_FANOUT");
        (void)snprintf(out->reason, sizeof(out->reason),
                       "value is sufficient but too few independent UTXOs exist for the requested concurrency");
    }
}

bool wallet_liquidity_plan_compute(
    const struct coin_entry *available, size_t num_available,
    int64_t agent_available_zat, int64_t recipient_value_zat,
    int64_t maximum_fee_zat, int64_t fanout_maximum_fee_zat,
    int requested_concurrency, struct wallet_liquidity_plan *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!wallet_liquidity_request_valid(available, num_available,
                                        agent_available_zat,
                                        recipient_value_zat, maximum_fee_zat,
                                        fanout_maximum_fee_zat,
                                        requested_concurrency)) {
        (void)snprintf(out->status, sizeof(out->status), "INVALID_REQUEST");
        (void)snprintf(out->reason, sizeof(out->reason),
                       "positive value, non-negative fees, and concurrency 1..50 are required");
        return false;
    }

    out->requested_concurrency = requested_concurrency;
    out->recipient_value_zat = recipient_value_zat;
    out->maximum_fee_zat = maximum_fee_zat;
    out->fanout_maximum_fee_zat = fanout_maximum_fee_zat;
    out->agent_available_zat = agent_available_zat;
    if (!wallet_liquidity_plan_fill_amounts(out))
        return false;

    if (num_available > SIZE_MAX / sizeof(struct coin_entry))
        return false;
    struct coin_entry *working = zcl_malloc(
        num_available * sizeof(*working), "wallet_liquidity_working");
    struct coin_entry *picked = zcl_malloc(
        num_available * sizeof(*picked), "wallet_liquidity_picked");
    if ((!working || !picked) && num_available != 0) {
        free(working);
        free(picked);
        return false;
    }
    if (num_available != 0)
        memcpy(working, available, num_available * sizeof(*working));
    if (!wallet_liquidity_sum_transparent(working, num_available,
                                          &out->transparent_available_zat)) {
        free(working);
        free(picked);
        return false;
    }
    wallet_liquidity_measure_slots(working, num_available, picked,
                                   requested_concurrency, out);
    free(working);
    free(picked);

    wallet_liquidity_plan_finish(out, requested_concurrency);
    return true;
}

static bool wallet_tx_args_valid(const struct wallet *w,
                                 const struct coin_entry *selected,
                                 size_t num_selected,
                                 const struct tx_out *outputs,
                                 size_t num_outputs,
                                 const struct wallet_tx *wtx_out,
                                 const char **error)
{
    if (!w || !selected || !outputs || !wtx_out || !error) {
        if (error) *error = "Invalid transaction arguments";
        return false;
    }
    if (num_selected == 0 || num_selected > 4096 || num_outputs == 0 ||
        num_outputs > 256) {
        *error = "Invalid number of inputs or outputs";
        return false;
    }
    return true;
}

static bool wallet_sum_explicit_inputs(const struct coin_entry *selected,
                                       size_t num_selected,
                                       int64_t *input_value_out,
                                       const char **error)
{
    int64_t input_value = 0;
    for (size_t i = 0; i < num_selected; i++) {
        if (!selected[i].wtx || !selected[i].spendable ||
            selected[i].i >= selected[i].wtx->tx.num_vout) {
            *error = "Explicit input is not spendable";
            return false;
        }
        int64_t value = selected[i].wtx->tx.vout[selected[i].i].value;
        if (value < 0 || input_value > INT64_MAX - value) {
            *error = "Explicit input value overflow";
            return false;
        }
        input_value += value;
        for (size_t j = 0; j < i; j++) {
            if (selected[j].i == selected[i].i &&
                uint256_eq(&selected[j].wtx->tx.hash,
                           &selected[i].wtx->tx.hash)) {
                *error = "Duplicate explicit input";
                return false;
            }
        }
    }
    *input_value_out = input_value;
    return true;
}

static bool wallet_sum_explicit_outputs(const struct tx_out *outputs,
                                        size_t num_outputs,
                                        int64_t *output_value_out,
                                        const char **error)
{
    int64_t output_value = 0;
    for (size_t i = 0; i < num_outputs; i++) {
        int64_t value = outputs[i].value;
        if (value < 0 || output_value > INT64_MAX - value) {
            *error = "Explicit output value overflow";
            return false;
        }
        output_value += value;
    }
    *output_value_out = output_value;
    return true;
}

static bool wallet_explicit_amounts_cover_fee(int64_t input_value,
                                              int64_t output_value,
                                              int64_t fee,
                                              const char **error)
{
    if (fee < 0 || output_value > INT64_MAX - fee ||
        input_value < output_value + fee) {
        *error = "Explicit inputs do not cover outputs and fee";
        return false;
    }
    return true;
}

static void wallet_tx_set_version_for_epoch(struct wallet_tx *wtx_out,
                                            int epoch, int height)
{
    if (epoch >= UPGRADE_SAPLING) {
        wtx_out->tx.overwintered = true;
        wtx_out->tx.version = SAPLING_TX_VERSION;
        wtx_out->tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        wtx_out->tx.expiry_height = (uint32_t)(height + 20);
    } else if (epoch >= UPGRADE_OVERWINTER) {
        wtx_out->tx.overwintered = true;
        wtx_out->tx.version = OVERWINTER_TX_VERSION;
        wtx_out->tx.version_group_id = OVERWINTER_VERSION_GROUP_ID;
        wtx_out->tx.expiry_height = (uint32_t)(height + 20);
    }
}

static bool wallet_tx_build_explicit(struct wallet *w,
                                     struct wallet_tx *wtx_out,
                                     const struct coin_entry *selected,
                                     size_t num_selected,
                                     const struct tx_out *outputs,
                                     size_t num_outputs,
                                     int64_t input_value,
                                     int64_t output_value,
                                     int64_t fee,
                                     const char **error)
{
    bool need_change = input_value > output_value + fee;
    if (!transaction_alloc(&wtx_out->tx, num_selected,
                           num_outputs + (need_change ? 1 : 0))) {
        *error = "Transaction allocation failed";
        return false;
    }
    for (size_t i = 0; i < num_outputs; i++)
        wtx_out->tx.vout[i] = outputs[i];
    if (need_change) {
        struct pubkey change_pk;
        if (!wallet_get_key_from_pool(w, &change_pk)) {
            transaction_free(&wtx_out->tx);
            *error = "Cannot get change address";
            return false;
        }
        struct tx_destination change_dest = {
            .type = DEST_KEY_ID, .id.key = pubkey_get_id(&change_pk),
        };
        wtx_out->tx.vout[num_outputs].value = input_value - output_value - fee;
        script_for_destination(&wtx_out->tx.vout[num_outputs].script_pub_key,
                               &change_dest);
    }
    for (size_t i = 0; i < num_selected; i++) {
        wtx_out->tx.vin[i].prevout.hash = selected[i].wtx->tx.hash;
        wtx_out->tx.vin[i].prevout.n = selected[i].i;
        wtx_out->tx.vin[i].sequence = UINT32_MAX - 1;
    }
    return true;
}

bool wallet_create_transaction_selected(struct wallet *w,
                                        const struct coin_entry *selected,
                                        size_t num_selected,
                                        const struct tx_out *outputs,
                                        size_t num_outputs,
                                        struct wallet_tx *wtx_out,
                                        int64_t *fee_out,
                                        const char **error)
{
    if (!wallet_tx_args_valid(w, selected, num_selected, outputs, num_outputs,
                              wtx_out, error))
        return false;

    int64_t input_value = 0, output_value = 0;
    if (!wallet_sum_explicit_inputs(selected, num_selected, &input_value,
                                    error))
        return false;
    if (!wallet_sum_explicit_outputs(outputs, num_outputs, &output_value,
                                     error))
        return false;
    int64_t fee = wallet_default_fee(w);
    if (!wallet_explicit_amounts_cover_fee(input_value, output_value, fee,
                                           error))
        return false;

    const struct chain_params *cp = chain_params_get();
    zcl_mutex_lock(&w->cs);
    int height = w->best_block_height;
    zcl_mutex_unlock(&w->cs);
    memset(wtx_out, 0, sizeof(*wtx_out));
    transaction_init(&wtx_out->tx);
    int epoch = consensus_current_epoch(height, &cp->consensus);
    wallet_tx_set_version_for_epoch(wtx_out, epoch, height);

    if (!wallet_tx_build_explicit(w, wtx_out, selected, num_selected, outputs,
                                  num_outputs, input_value, output_value, fee,
                                  error))
        return false;
    if (!wallet_sign_selected_inputs(w, wtx_out, selected, num_selected,
                                     height, error))
        return false;
    transaction_compute_hash(&wtx_out->tx);
    wtx_out->time_received = GetTime();
    wtx_out->from_me = true;
    wtx_out->used = true;
    if (fee_out) *fee_out = fee;
    return true;
}
