/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2015 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_POLICY_FEES_H
#define ZCL_POLICY_FEES_H

#include "core/amount.h"
#include "core/uint256.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <math.h>

#define DEFAULT_DECAY 0.998
#define MAX_BLOCK_CONFIRMS 25
#define MIN_SUCCESS_PCT 0.85
#define UNLIKELY_PCT 0.5
#define SUFFICIENT_FEETXS 1.0
#define SUFFICIENT_PRITXS 0.2
#define MIN_FEERATE_VAL 10.0
#define MAX_FEERATE_VAL 1e7
#define INF_FEERATE_VAL ((double)MAX_MONEY)
#define MIN_PRIORITY_VAL 10.0
#define MAX_PRIORITY_VAL 1e16
#define INF_PRIORITY_VAL (1e9 * (double)MAX_MONEY)
#define FEE_SPACING 1.1
#define PRI_SPACING 2.0

struct tx_confirm_stats {
    double *buckets;
    size_t num_buckets;

    double *tx_ct_avg;
    int *cur_block_tx_ct;

    double **conf_avg;
    int **cur_block_conf;
    size_t max_confirms;

    double *avg;
    double *cur_block_val;

    double decay;

    int **unconf_txs;
    int *old_unconf_txs;
};

void tx_confirm_stats_init(struct tx_confirm_stats *s);
void tx_confirm_stats_free(struct tx_confirm_stats *s);
void tx_confirm_stats_setup(struct tx_confirm_stats *s,
                            const double *default_buckets, size_t num_defaults,
                            unsigned int max_confirms, double decay);
unsigned int tx_confirm_stats_find_bucket(const struct tx_confirm_stats *s,
                                          double val);
void tx_confirm_stats_clear_current(struct tx_confirm_stats *s,
                                    unsigned int block_height);
void tx_confirm_stats_record(struct tx_confirm_stats *s,
                             int blocks_to_confirm, double val);
unsigned int tx_confirm_stats_new_tx(struct tx_confirm_stats *s,
                                     unsigned int block_height, double val);
void tx_confirm_stats_remove_tx(struct tx_confirm_stats *s,
                                unsigned int entry_height,
                                unsigned int best_seen_height,
                                unsigned int bucket_index);
void tx_confirm_stats_update_averages(struct tx_confirm_stats *s);
double tx_confirm_stats_estimate_median(struct tx_confirm_stats *s,
                                        int conf_target,
                                        double sufficient_tx_val,
                                        double min_success,
                                        bool require_greater,
                                        unsigned int block_height);
unsigned int tx_confirm_stats_max_confirms(const struct tx_confirm_stats *s);

struct tx_stats_info {
    struct tx_confirm_stats *stats;
    unsigned int block_height;
    unsigned int bucket_index;
};

struct tx_stats_entry {
    struct uint256 hash;
    struct tx_stats_info info;
    bool used;
};

#define TX_STATS_MAP_INITIAL_CAP 256

struct block_policy_estimator {
    struct fee_rate min_tracked_fee;
    double min_tracked_priority;
    unsigned int best_seen_height;

    struct tx_stats_entry *map_entries;
    size_t num_map_entries;
    size_t map_cap;

    struct tx_confirm_stats fee_stats;
    struct tx_confirm_stats pri_stats;

    struct fee_rate fee_likely;
    struct fee_rate fee_unlikely;
    double pri_likely;
    double pri_unlikely;
};

void block_policy_estimator_init(struct block_policy_estimator *e,
                                 const struct fee_rate *min_relay_fee);
void block_policy_estimator_free(struct block_policy_estimator *e);

struct mempool_entry;

void policy_process_transaction(struct block_policy_estimator *e,
                                const struct mempool_entry *entry,
                                bool current_estimate);
void policy_process_block_tx(struct block_policy_estimator *e,
                             unsigned int block_height,
                             const struct mempool_entry *entry);
void policy_process_block(struct block_policy_estimator *e,
                          unsigned int block_height,
                          struct mempool_entry *entries, size_t num_entries,
                          bool current_estimate);
void policy_remove_tx(struct block_policy_estimator *e,
                      const struct uint256 *hash);

bool policy_is_fee_data_point(const struct block_policy_estimator *e,
                              const struct fee_rate *fee, double pri);
bool policy_is_pri_data_point(const struct block_policy_estimator *e,
                              const struct fee_rate *fee, double pri);

struct fee_rate policy_estimate_fee(struct block_policy_estimator *e,
                                    int conf_target);
double policy_estimate_priority(struct block_policy_estimator *e,
                                int conf_target);

#endif
