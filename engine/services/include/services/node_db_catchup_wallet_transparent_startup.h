/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: startup-only transparent replay acceleration. */
#ifndef Z23_NODE_DB_CATCHUP_WALLET_TRANSPARENT_STARTUP_H
#define Z23_NODE_DB_CATCHUP_WALLET_TRANSPARENT_STARTUP_H
#include "services/node_db_catchup_wallet_transparent.h"
struct transparent_replay_filter;
/* Only while startup holds the wallet quiescent before services begin. A NULL
 * filter always uses legacy replay. Free before wallet teardown or reinit. */
struct transparent_replay_filter *transparent_replay_filter_new(struct wallet *wallet);
void transparent_replay_filter_free(struct transparent_replay_filter *filter);
#ifdef ZCL_TESTING
struct uint256;
enum transparent_filter_probe { TRANSPARENT_FILTER_ABSENT, TRANSPARENT_FILTER_POSSIBLE };
enum transparent_filter_probe transparent_replay_filter_test_maybe(const struct transparent_replay_filter *filter, const struct uint256 *hash);
void transparent_replay_filter_test_saturate(struct transparent_replay_filter *filter);
#endif
struct transparent_replay_result node_db_catchup_wallet_transparent_indexed(
    struct main_state *state, struct wallet *wallet, const char *datadir,
    int start, int end, int reference_height, const uint8_t endpoint_hash[32],
    const uint8_t scan_identity[32], struct transparent_replay_filter *filter);
#endif
