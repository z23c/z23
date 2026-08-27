/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2015 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "policy/fees.h"
#include "validation/txmempool.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"

/* --- tx_confirm_stats --- */

void tx_confirm_stats_init(struct tx_confirm_stats *s)
{
    memset(s, 0, sizeof(*s));
    s->decay = DEFAULT_DECAY;
}

void tx_confirm_stats_free(struct tx_confirm_stats *s)
{
    free(s->buckets);
    free(s->tx_ct_avg);
    free(s->cur_block_tx_ct);
    free(s->avg);
    free(s->cur_block_val);
    free(s->old_unconf_txs);
    for (size_t i = 0; i < s->max_confirms; i++) {
        free(s->conf_avg[i]);
        free(s->cur_block_conf[i]);
        free(s->unconf_txs[i]);
    }
    free(s->conf_avg);
    free(s->cur_block_conf);
    free(s->unconf_txs);
}

void tx_confirm_stats_setup(struct tx_confirm_stats *s,
                            const double *default_buckets, size_t num_defaults,
                            unsigned int max_confirms, double decay)
{
    s->decay = decay;
    s->num_buckets = num_defaults + 1;
    s->max_confirms = max_confirms;

    s->buckets = zcl_calloc(s->num_buckets, sizeof(double), "fee_buckets");
    for (size_t i = 0; i < num_defaults; i++)
        s->buckets[i] = default_buckets[i];
    s->buckets[num_defaults] = HUGE_VAL;

    s->tx_ct_avg = zcl_calloc(s->num_buckets, sizeof(double), "fee_tx_ct_avg");
    s->cur_block_tx_ct = zcl_calloc(s->num_buckets, sizeof(int), "fee_block_tx_ct");
    s->avg = zcl_calloc(s->num_buckets, sizeof(double), "fee_avg");
    s->cur_block_val = zcl_calloc(s->num_buckets, sizeof(double), "fee_block_val");
    s->old_unconf_txs = zcl_calloc(s->num_buckets, sizeof(int), "fee_old_unconf");

    s->conf_avg = zcl_calloc(max_confirms, sizeof(double *), "fee_conf_avg");
    s->cur_block_conf = zcl_calloc(max_confirms, sizeof(int *), "fee_block_conf");
    s->unconf_txs = zcl_calloc(max_confirms, sizeof(int *), "fee_unconf_txs");
    for (unsigned int i = 0; i < max_confirms; i++) {
        s->conf_avg[i] = zcl_calloc(s->num_buckets, sizeof(double), "fee_conf_avg_row");
        s->cur_block_conf[i] = zcl_calloc(s->num_buckets, sizeof(int), "fee_block_conf_row");
        s->unconf_txs[i] = zcl_calloc(s->num_buckets, sizeof(int), "fee_unconf_row");
    }
}

unsigned int tx_confirm_stats_find_bucket(const struct tx_confirm_stats *s,
                                          double val)
{
    for (size_t i = 0; i < s->num_buckets; i++)
        if (s->buckets[i] >= val)
            return (unsigned int)i;
    return (unsigned int)(s->num_buckets - 1);
}

void tx_confirm_stats_clear_current(struct tx_confirm_stats *s,
                                    unsigned int block_height)
{
    for (size_t j = 0; j < s->num_buckets; j++) {
        size_t slot = block_height % s->max_confirms;
        s->old_unconf_txs[j] += s->unconf_txs[slot][j];
        s->unconf_txs[slot][j] = 0;
        for (size_t i = 0; i < s->max_confirms; i++)
            s->cur_block_conf[i][j] = 0;
        s->cur_block_tx_ct[j] = 0;
        s->cur_block_val[j] = 0;
    }
}

void tx_confirm_stats_record(struct tx_confirm_stats *s,
                             int blocks_to_confirm, double val)
{
    if (blocks_to_confirm < 1)
        return;
    unsigned int bi = tx_confirm_stats_find_bucket(s, val);
    for (size_t i = (size_t)blocks_to_confirm; i <= s->max_confirms; i++)
        s->cur_block_conf[i - 1][bi]++;
    s->cur_block_tx_ct[bi]++;
    s->cur_block_val[bi] += val;
}

unsigned int tx_confirm_stats_new_tx(struct tx_confirm_stats *s,
                                     unsigned int block_height, double val)
{
    unsigned int bi = tx_confirm_stats_find_bucket(s, val);
    size_t slot = block_height % s->max_confirms;
    s->unconf_txs[slot][bi]++;
    return bi;
}

void tx_confirm_stats_remove_tx(struct tx_confirm_stats *s,
                                unsigned int entry_height,
                                unsigned int best_seen_height,
                                unsigned int bucket_index)
{
    int blocks_ago = (int)best_seen_height - (int)entry_height;
    if (best_seen_height == 0)
        blocks_ago = 0;
    if (blocks_ago < 0)
        return;

    if ((unsigned int)blocks_ago >= s->max_confirms) {
        if (s->old_unconf_txs[bucket_index] > 0)
            s->old_unconf_txs[bucket_index]--;
    } else {
        size_t slot = entry_height % s->max_confirms;
        if (s->unconf_txs[slot][bucket_index] > 0)
            s->unconf_txs[slot][bucket_index]--;
    }
}

void tx_confirm_stats_update_averages(struct tx_confirm_stats *s)
{
    for (size_t j = 0; j < s->num_buckets; j++) {
        for (size_t i = 0; i < s->max_confirms; i++)
            s->conf_avg[i][j] = s->conf_avg[i][j] * s->decay +
                                s->cur_block_conf[i][j];
        s->avg[j] = s->avg[j] * s->decay + s->cur_block_val[j];
        s->tx_ct_avg[j] = s->tx_ct_avg[j] * s->decay + s->cur_block_tx_ct[j];
    }
}

double tx_confirm_stats_estimate_median(struct tx_confirm_stats *s,
                                        int conf_target,
                                        double sufficient_tx_val,
                                        double min_success,
                                        bool require_greater,
                                        unsigned int block_height)
{
    double n_conf = 0;
    double total_num = 0;
    int extra_num = 0;

    int max_bucket_index = (int)s->num_buckets - 1;
    unsigned int start_bucket = require_greater ? (unsigned int)max_bucket_index : 0;
    int step = require_greater ? -1 : 1;

    unsigned int cur_near = start_bucket;
    unsigned int best_near = start_bucket;
    unsigned int cur_far = start_bucket;
    unsigned int best_far = start_bucket;
    bool found = false;
    unsigned int bins = (unsigned int)s->max_confirms;

    for (int bucket = (int)start_bucket;
         bucket >= 0 && bucket <= max_bucket_index; bucket += step) {
        cur_far = (unsigned int)bucket;
        n_conf += s->conf_avg[conf_target - 1][bucket];
        total_num += s->tx_ct_avg[bucket];
        for (unsigned int ct = (unsigned int)conf_target;
             ct < s->max_confirms; ct++)
            extra_num += s->unconf_txs[(block_height - ct) % bins][bucket];
        extra_num += s->old_unconf_txs[bucket];

        if (total_num >= sufficient_tx_val / (1.0 - s->decay)) {
            double cur_pct = n_conf / (total_num + extra_num);
            if (require_greater && cur_pct < min_success)
                break;
            if (!require_greater && cur_pct > min_success)
                break;
            found = true;
            n_conf = 0;
            total_num = 0;
            extra_num = 0;
            best_near = cur_near;
            best_far = cur_far;
            cur_near = (unsigned int)(bucket + step);
        }
    }

    double median = -1;
    double tx_sum = 0;
    unsigned int min_b = best_near < best_far ? best_near : best_far;
    unsigned int max_b = best_near > best_far ? best_near : best_far;
    for (unsigned int j = min_b; j <= max_b; j++)
        tx_sum += s->tx_ct_avg[j];
    if (found && tx_sum != 0) {
        tx_sum /= 2;
        for (unsigned int j = min_b; j <= max_b; j++) {
            if (s->tx_ct_avg[j] < tx_sum)
                tx_sum -= s->tx_ct_avg[j];
            else {
                median = s->avg[j] / s->tx_ct_avg[j];
                break;
            }
        }
    }
    return median;
}

unsigned int tx_confirm_stats_max_confirms(const struct tx_confirm_stats *s)
{
    return (unsigned int)s->max_confirms;
}

/* --- block_policy_estimator --- */

void block_policy_estimator_init(struct block_policy_estimator *e,
                                 const struct fee_rate *min_relay_fee)
{
    memset(e, 0, sizeof(*e));

    if (min_relay_fee->satoshis_per_k < (CAmount)MIN_FEERATE_VAL)
        e->min_tracked_fee.satoshis_per_k = (CAmount)MIN_FEERATE_VAL;
    else
        e->min_tracked_fee = *min_relay_fee;

    double free_thresh = allow_free_threshold();
    e->min_tracked_priority = free_thresh < MIN_PRIORITY_VAL
                                  ? MIN_PRIORITY_VAL : free_thresh;

    size_t fee_cap = 128;
    double *fee_list = zcl_malloc(fee_cap * sizeof(double), "fee_list");
    if (!fee_list) {
        LOG_WARN("policy", "block_policy_estimator_init: fee_list alloc failed");
        return;
    }
    size_t fee_count = 0;
    for (double b = (double)fee_rate_get_fee_per_k(&e->min_tracked_fee);
         b <= MAX_FEERATE_VAL; b *= FEE_SPACING) {
        if (fee_count >= fee_cap) {
            fee_cap *= 2;
            double *fee_tmp = zcl_realloc(fee_list, fee_cap * sizeof(double),
                                          "fee_list");
            if (!fee_tmp) {
                LOG_WARN("policy",
                         "block_policy_estimator_init: fee_list realloc failed");
                free(fee_list);
                return;
            }
            fee_list = fee_tmp;
        }
        fee_list[fee_count++] = b;
    }
    tx_confirm_stats_init(&e->fee_stats);
    tx_confirm_stats_setup(&e->fee_stats, fee_list, fee_count,
                           MAX_BLOCK_CONFIRMS, DEFAULT_DECAY);
    free(fee_list);

    size_t pri_cap = 128;
    double *pri_list = zcl_malloc(pri_cap * sizeof(double), "pri_list");
    if (!pri_list) {
        LOG_WARN("policy", "block_policy_estimator_init: pri_list alloc failed");
        return;
    }
    size_t pri_count = 0;
    for (double b = e->min_tracked_priority;
         b <= MAX_PRIORITY_VAL; b *= PRI_SPACING) {
        if (pri_count >= pri_cap) {
            pri_cap *= 2;
            double *pri_tmp = zcl_realloc(pri_list, pri_cap * sizeof(double),
                                          "pri_list");
            if (!pri_tmp) {
                LOG_WARN("policy",
                         "block_policy_estimator_init: pri_list realloc failed");
                free(pri_list);
                return;
            }
            pri_list = pri_tmp;
        }
        pri_list[pri_count++] = b;
    }
    tx_confirm_stats_init(&e->pri_stats);
    tx_confirm_stats_setup(&e->pri_stats, pri_list, pri_count,
                           MAX_BLOCK_CONFIRMS, DEFAULT_DECAY);
    free(pri_list);

    e->fee_unlikely.satoshis_per_k = 0;
    e->fee_likely.satoshis_per_k = (CAmount)INF_FEERATE_VAL;
    e->pri_unlikely = 0;
    e->pri_likely = INF_PRIORITY_VAL;

    e->map_cap = TX_STATS_MAP_INITIAL_CAP;
    e->map_entries = zcl_calloc(e->map_cap, sizeof(*e->map_entries), "fee_map_entries");
}

void block_policy_estimator_free(struct block_policy_estimator *e)
{
    free(e->map_entries);
    tx_confirm_stats_free(&e->fee_stats);
    tx_confirm_stats_free(&e->pri_stats);
}

static struct tx_stats_entry *find_stats_entry(struct block_policy_estimator *e,
                                                const struct uint256 *hash)
{
    for (size_t i = 0; i < e->num_map_entries; i++)
        if (e->map_entries[i].used &&
            uint256_eq(&e->map_entries[i].hash, hash))
            return &e->map_entries[i];
    return NULL;
}

static struct tx_stats_entry *insert_stats_entry(
    struct block_policy_estimator *e, const struct uint256 *hash)
{
    if (e->num_map_entries >= e->map_cap) {
        size_t newcap = e->map_cap * 2;
        void *tmp = zcl_realloc(e->map_entries,
                                newcap * sizeof(*e->map_entries), "fee_map_entries");
        if (!tmp)
            LOG_NULL("policy",
                     "insert_stats_entry: realloc fee_map_entries failed newcap=%zu",
                     newcap);
        e->map_entries = tmp;
        memset(e->map_entries + e->map_cap, 0,
               (newcap - e->map_cap) * sizeof(*e->map_entries));
        e->map_cap = newcap;
    }
    struct tx_stats_entry *ent = &e->map_entries[e->num_map_entries++];
    ent->hash = *hash;
    ent->used = true;
    memset(&ent->info, 0, sizeof(ent->info));
    return ent;
}

static void remove_stats_entry(struct block_policy_estimator *e,
                               struct tx_stats_entry *ent)
{
    size_t idx = (size_t)(ent - e->map_entries);
    ent->used = false;
    if (idx < e->num_map_entries - 1)
        *ent = e->map_entries[e->num_map_entries - 1];
    e->num_map_entries--;
}

bool policy_is_fee_data_point(const struct block_policy_estimator *e,
                              const struct fee_rate *fee, double pri)
{
    return (pri < e->min_tracked_priority &&
            fee->satoshis_per_k >= e->min_tracked_fee.satoshis_per_k) ||
           (pri < e->pri_unlikely &&
            fee->satoshis_per_k > e->fee_likely.satoshis_per_k);
}

bool policy_is_pri_data_point(const struct block_policy_estimator *e,
                              const struct fee_rate *fee, double pri)
{
    return (fee->satoshis_per_k < e->min_tracked_fee.satoshis_per_k &&
            pri >= e->min_tracked_priority) ||
           (fee->satoshis_per_k < e->fee_unlikely.satoshis_per_k &&
            pri > e->pri_likely);
}

void policy_process_transaction(struct block_policy_estimator *e,
                                const struct mempool_entry *entry,
                                bool current_estimate)
{
    unsigned int tx_height = entry->height;
    const struct uint256 *hash = &entry->tx.hash;

    struct tx_stats_entry *existing = find_stats_entry(e, hash);
    if (existing && existing->info.stats != NULL)
        return;

    if (tx_height < e->best_seen_height)
        return;
    if (!current_estimate)
        return;
    if (!entry->had_no_deps)
        return;

    struct fee_rate fr;
    fee_rate_init_from_fee(&fr, entry->fee, entry->tx_size);
    double cur_pri = mempool_entry_get_priority(entry, tx_height);

    struct tx_stats_entry *ent = existing ? existing :
                                 insert_stats_entry(e, hash);
    if (!ent)
        return; /* OOM growing the stats map (logged at the realloc site):
                 * skip this data point. The fee estimator is best-effort and
                 * its existing state is intact, so a clean skip is correct. */
    ent->info.block_height = tx_height;

    if (entry->fee == 0 || policy_is_pri_data_point(e, &fr, cur_pri)) {
        ent->info.stats = &e->pri_stats;
        ent->info.bucket_index =
            tx_confirm_stats_new_tx(&e->pri_stats, tx_height, cur_pri);
    } else if (policy_is_fee_data_point(e, &fr, cur_pri)) {
        ent->info.stats = &e->fee_stats;
        ent->info.bucket_index = tx_confirm_stats_new_tx(
            &e->fee_stats, tx_height,
            (double)fee_rate_get_fee_per_k(&fr));
    }
}

void policy_process_block_tx(struct block_policy_estimator *e,
                             unsigned int block_height,
                             const struct mempool_entry *entry)
{
    if (!entry->had_no_deps)
        return;

    int blocks_to_confirm = (int)block_height - (int)entry->height;
    if (blocks_to_confirm <= 0)
        return;

    struct fee_rate fr;
    fee_rate_init_from_fee(&fr, entry->fee, entry->tx_size);
    double cur_pri = mempool_entry_get_priority(entry, block_height);

    if (entry->fee == 0 || policy_is_pri_data_point(e, &fr, cur_pri))
        tx_confirm_stats_record(&e->pri_stats, blocks_to_confirm, cur_pri);
    else if (policy_is_fee_data_point(e, &fr, cur_pri))
        tx_confirm_stats_record(&e->fee_stats, blocks_to_confirm,
                                (double)fee_rate_get_fee_per_k(&fr));
}

void policy_process_block(struct block_policy_estimator *e,
                          unsigned int block_height,
                          struct mempool_entry *entries, size_t num_entries,
                          bool current_estimate)
{
    if (block_height <= e->best_seen_height)
        return;
    e->best_seen_height = block_height;

    if (!current_estimate)
        return;

    e->pri_likely = tx_confirm_stats_estimate_median(
        &e->pri_stats, 2, SUFFICIENT_PRITXS, MIN_SUCCESS_PCT,
        true, block_height);
    if (e->pri_likely == -1)
        e->pri_likely = INF_PRIORITY_VAL;

    double fee_likely_est = tx_confirm_stats_estimate_median(
        &e->fee_stats, 2, SUFFICIENT_FEETXS, MIN_SUCCESS_PCT,
        true, block_height);
    e->fee_likely.satoshis_per_k = fee_likely_est == -1
                                       ? (CAmount)INF_FEERATE_VAL
                                       : (CAmount)fee_likely_est;

    e->pri_unlikely = tx_confirm_stats_estimate_median(
        &e->pri_stats, 10, SUFFICIENT_PRITXS, UNLIKELY_PCT,
        false, block_height);
    if (e->pri_unlikely == -1)
        e->pri_unlikely = 0;

    double fee_unlikely_est = tx_confirm_stats_estimate_median(
        &e->fee_stats, 10, SUFFICIENT_FEETXS, UNLIKELY_PCT,
        false, block_height);
    e->fee_unlikely.satoshis_per_k = fee_unlikely_est == -1
                                         ? 0
                                         : (CAmount)fee_unlikely_est;

    tx_confirm_stats_clear_current(&e->fee_stats, block_height);
    tx_confirm_stats_clear_current(&e->pri_stats, block_height);

    for (size_t i = 0; i < num_entries; i++)
        policy_process_block_tx(e, block_height, &entries[i]);

    tx_confirm_stats_update_averages(&e->fee_stats);
    tx_confirm_stats_update_averages(&e->pri_stats);
}

void policy_remove_tx(struct block_policy_estimator *e,
                      const struct uint256 *hash)
{
    struct tx_stats_entry *ent = find_stats_entry(e, hash);
    if (!ent)
        return;
    if (ent->info.stats != NULL)
        tx_confirm_stats_remove_tx(ent->info.stats, ent->info.block_height,
                                   e->best_seen_height,
                                   ent->info.bucket_index);
    remove_stats_entry(e, ent);
}

struct fee_rate policy_estimate_fee(struct block_policy_estimator *e,
                                    int conf_target)
{
    struct fee_rate r;
    fee_rate_init(&r);
    if (conf_target <= 0 ||
        (unsigned int)conf_target >
            tx_confirm_stats_max_confirms(&e->fee_stats))
        return r;
    double median = tx_confirm_stats_estimate_median(
        &e->fee_stats, conf_target, SUFFICIENT_FEETXS, MIN_SUCCESS_PCT,
        true, e->best_seen_height);
    if (median < 0)
        return r;
    r.satoshis_per_k = (CAmount)median;
    return r;
}

double policy_estimate_priority(struct block_policy_estimator *e,
                                int conf_target)
{
    if (conf_target <= 0 ||
        (unsigned int)conf_target >
            tx_confirm_stats_max_confirms(&e->pri_stats))
        return -1;
    return tx_confirm_stats_estimate_median(
        &e->pri_stats, conf_target, SUFFICIENT_PRITXS, MIN_SUCCESS_PCT,
        true, e->best_seen_height);
}
